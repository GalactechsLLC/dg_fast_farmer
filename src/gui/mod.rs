use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use std::io::Error;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ratatui::style::Stylize;
use ratatui::{prelude::*, widgets::*};

use tui_logger::*;

use crate::farmer::Farmer;
use crate::farmer::config::Config;
use crate::harvesters::{Harvester, ProofHandler, SignatureHandler};
use crate::routes::metrics;
use crate::tasks::blockchain_state_updater::update_blockchain;
use crate::tasks::pool_state_updater::pool_updater;
use dg_xch_clients::api::pool::DefaultPoolClient;
use dg_xch_core::blockchain::blockchain_state::BlockchainState;
use dg_xch_core::protocols::farmer::{FarmerSharedState, MostRecentSignagePoint, PlotCounts};
use log::{LevelFilter, error};
use portfu::prelude::ServerBuilder;
use sysinfo::System;
use time::OffsetDateTime;
use time::macros::format_description;
use tokio::sync::{Mutex, RwLock};
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::sleep;
use tokio::{join, select};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Action {
    None,
    Quit,
    Tab,
    StartServer,
    StopServer,
}

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct SysInfo {
    pub cpu_usage: u16,
    pub ram_used: u64,
    pub ram_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
}

pub struct GuiState<T> {
    pub system_info: Arc<Mutex<SysInfo>>,
    pub farmer_state: Arc<FarmerSharedState<T>>,
}

impl<T> GuiState<T> {
    fn new(shared_state: Arc<FarmerSharedState<T>>) -> GuiState<T> {
        GuiState {
            system_info: Default::default(),
            farmer_state: shared_state,
        }
    }
}

pub async fn bootstrap<
    T: Sync + Send + 'static,
    C: Sync + Send + Clone + 'static,
    H: Harvester<T, H, C> + Sync + Send + 'static,
    O: ProofHandler<T, H, C> + Sync + Send + 'static,
    S: SignatureHandler<T, H, C> + Sync + Send + 'static,
>(
    shared_state: Arc<FarmerSharedState<T>>,
    config: Arc<RwLock<Config<C>>>,
) -> Result<(), Error> {
    init_logger(LevelFilter::Info).unwrap();
    set_default_level(LevelFilter::Info);
    enable_raw_mode()?;
    let harvester = H::load(shared_state.clone(), config.clone()).await?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let gui_state = Arc::new(GuiState::new(shared_state.clone()));
    let farmer_gui_state = gui_state.clone();
    let farmer_config = config.clone();
    let farmer_thread = tokio::spawn(async move {
        let farmer_state = farmer_gui_state.farmer_state.clone();
        let pool_state = farmer_state.clone();
        let pool_config = farmer_config.clone();
        let pool_state_handle: JoinHandle<()> =
            tokio::spawn(async move { pool_updater(pool_state, pool_config).await });
        let pool_client = Arc::new(DefaultPoolClient::new());
        let farmer = Farmer::<DefaultPoolClient, O, S, T, H, C>::new(
            farmer_state,
            pool_client,
            harvester,
            farmer_config,
        )
        .await?;
        let client_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
            farmer.run().await;
            Ok(())
        });
        let _ = join!(pool_state_handle, client_handle);
        Ok::<(), Error>(())
    });
    let fullnode_state = gui_state.clone();
    let fullnode_config = config.clone();
    let fullnode_thread = tokio::spawn(async move {
        update_blockchain(fullnode_state.farmer_state.clone(), fullnode_config).await
    });
    let sys_info_gui_state = gui_state.clone();
    let sys_info_thread = tokio::spawn(async move {
        let mut system = System::new();
        system.refresh_cpu_all();
        system.refresh_memory();
        sleep(Duration::from_secs(3)).await;
        system.refresh_cpu_all();
        system.refresh_memory();
        loop {
            let results = spawn_blocking(move || {
                system.refresh_cpu_all();
                system.refresh_memory();
                let si = SysInfo {
                    cpu_usage: system.global_cpu_usage() as u16,
                    ram_used: system.used_memory(),
                    ram_total: system.total_memory(),
                    swap_used: system.used_swap(),
                    swap_total: system.total_swap(),
                };
                (system, si)
            })
            .await;
            let (sys, sys_info) = results.unwrap_or_else(|e| {
                error!("Error Joining System Loading Thread: {e:?}");
                (System::new(), Default::default())
            });
            *sys_info_gui_state.system_info.lock().await = sys_info;
            system = sys;
            if !sys_info_gui_state
                .farmer_state
                .signal
                .load(Ordering::Relaxed)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    let metrics_settings = config.read().await.metrics.clone().unwrap_or_default();
    let metrics_state = shared_state.clone();
    let server_handle = if metrics_settings.enabled {
        tokio::spawn(async move {
            select! {
                _ = ServerBuilder::default()
                    .host("0.0.0.0".to_string())
                    .port(metrics_settings.port)
                    .shared_state::<Arc<FarmerSharedState<T>>>(metrics_state.clone())
                    .register(metrics::<T>::default())
                    .build().run()
                => {
                    Ok(())
                }
                _ = async {
                    loop {
                        if !metrics_state.signal.load(Ordering::Relaxed) {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                } => {
                    Ok(())
                }
            }
        })
    } else {
        tokio::spawn(async move { Ok::<(), Error>(()) })
    };
    let (fn_res, sys_res, gui_res, farmer_res, server_res) = join!(
        fullnode_thread,
        sys_info_thread,
        run_gui(&mut terminal, gui_state),
        farmer_thread,
        server_handle
    );
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    if let Err(err) = fn_res {
        eprintln!("Error Joining Fullnode Thread {err:?}");
    }
    if let Err(err) = sys_res {
        eprintln!("Error Joining SysInfo Thread {err:?}");
    }
    if let Err(err) = gui_res {
        eprintln!("Error Joining GUI Thread {err:?}");
    }
    if let Err(err) = farmer_res {
        eprintln!("Error Joining Farmer Thread {err:?}");
    }
    if let Err(err) = server_res {
        eprintln!("Error Joining Server Thread {err:?}");
    }
    Ok(())
}

async fn run_gui<B: Backend, T>(
    terminal: &mut Terminal<B>,
    gui_state: Arc<GuiState<T>>,
) -> std::io::Result<()> {
    loop {
        {
            let farmer_state = gui_state.farmer_state.plot_counts.clone();
            let sys_info = *gui_state.system_info.lock().await;
            let most_recent_sp = *gui_state.farmer_state.most_recent_sp.read().await;
            let fullnode_state = gui_state.farmer_state.fullnode_state.read().await.clone();
            terminal.draw(|f| ui(f, farmer_state, fullnode_state, most_recent_sp, &sys_info))?;
        }
        if event::poll(Duration::from_millis(25))?
            && let Event::Key(event) = event::read()?
        {
            match event.code {
                KeyCode::Esc => {
                    gui_state
                        .farmer_state
                        .signal
                        .store(false, Ordering::Relaxed);
                }
                KeyCode::Char('c') => {
                    if event.modifiers == KeyModifiers::CONTROL {
                        gui_state
                            .farmer_state
                            .signal
                            .store(false, Ordering::Relaxed);
                    }
                }
                _ => {}
            }
        }
        if !gui_state.farmer_state.signal.load(Ordering::Relaxed) {
            break;
        }
    }
    Ok(())
}

fn ui(
    f: &mut Frame,
    plot_counts: Arc<PlotCounts>,
    fullnode_state: Option<BlockchainState>,
    most_recent_sp: MostRecentSignagePoint,
    sys_info: &SysInfo,
) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(100)].as_ref())
        .split(size);

    let block = Block::default().on_black().gray();
    f.render_widget(block, size);

    let wrapper_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(chunks[0]);

    let overview_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage(10),
                Constraint::Percentage(30),
                Constraint::Percentage(31),
                Constraint::Percentage(10),
                Constraint::Percentage(9),
                Constraint::Percentage(10),
            ]
            .as_ref(),
        )
        .split(wrapper_chunks[0]);

    let farmer_info = {
        format!(
            "\t  Process State: Running\n\
             \t  Plot Count: {:#?}\n\
             \t  Total Space: {} ({:#?})\n\
             \t  Most Recent Signage Point: \n    {:#?} ({:#?})",
            plot_counts.og_plot_count.load(Ordering::Relaxed)
                + plot_counts.nft_plot_count.load(Ordering::Relaxed)
                + plot_counts.compressed_plot_count.load(Ordering::Relaxed),
            bytefmt::format_to(
                plot_counts.total_plot_space.load(Ordering::Relaxed) as u64,
                bytefmt::Unit::TIB
            ),
            plot_counts.total_plot_space.load(Ordering::Relaxed),
            most_recent_sp.hash,
            most_recent_sp.index,
        )
    };

    let mut height: u32 = 0;
    let mut timestamp: u64 = 0;
    let mut sync: bool = false;
    let mut difficulty: u64 = 0;
    let mut space: u128 = 0;
    let mut mempool_size: u64 = 0;

    if let Some(full_node) = fullnode_state {
        if let Some(peak) = full_node.peak {
            height = peak.height;
            if let Some(_timestamp) = peak.timestamp {
                timestamp = _timestamp;
            }
        }
        sync = full_node.sync.synced;
        difficulty = full_node.difficulty;
        space = full_node.space;
        mempool_size = full_node.mempool_size;
    }
    let formatted_timestamp: String = if timestamp != 0 {
        let datetime = OffsetDateTime::from_unix_timestamp(timestamp as i64)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let format = format_description!("[day]-[month]-[year] [hour]:[minute]:[second]");
        datetime.format(&format).unwrap_or(format!("{datetime}"))
    } else {
        "N/A".to_string()
    };
    let fullnode_info = {
        format!(
            "\t  Blockchain Sync: {:#?}\n\
            \t  Blockchain Height: {:#?}\n\
            \t  Timestamp: {}\n\
            \t  Blockchain Space: {:.3} EB\n\
            \t  Blockchain Difficulty: {:#?}\n\
            \t  Blockchain Mempool Size: {:#?}\n",
            sync,
            height,
            formatted_timestamp,
            (space as f64 / 1000_f64 / 1000_f64 / 1000_f64 / 1000_f64 / 1000_f64 / 1000_f64),
            difficulty,
            mempool_size,
        )
    };

    let farmer_content = Paragraph::new(farmer_info).block(
        Block::default()
            .title("Farmer Information: ")
            .borders(Borders::ALL),
    );
    let title = Paragraph::new(" __            __                  \n|_   _   _ |_ |_   _   _  _   _  _ \n|   (_| _) |_ |   (_| |  ||| (- |  \n\n To Select/Copy: Hold Shift   To Quit: ESC or CTL+C")
        .style(Style::default().fg(Color::Green)).block(
        Block::default(),
    ).alignment(Alignment::Center);
    f.render_widget(title, overview_chunks[0]);
    f.render_widget(farmer_content, overview_chunks[1]);
    let fullnode_content = Paragraph::new(fullnode_info).block(
        Block::default()
            .title("Fullnode Information: ")
            .borders(Borders::ALL),
    );
    f.render_widget(fullnode_content, overview_chunks[2]);
    let cpu_usage_widget = draw_gauge("System CPU Usage", sys_info.cpu_usage);
    f.render_widget(cpu_usage_widget, overview_chunks[3]);
    let ram_title = format!(
        "System RAM Usage: {:.2}Gb/{:.2}Gb",
        sys_info.ram_used as f32 / 1024f32 / 1024f32 / 1024f32,
        sys_info.ram_total as f32 / 1024f32 / 1024f32 / 1024f32
    );
    let ram_usage_widget = draw_gauge(
        &ram_title,
        ((sys_info.ram_used as f32 / sys_info.ram_total as f32) * 100f32) as u16,
    );
    f.render_widget(ram_usage_widget, overview_chunks[4]);
    let swap_title = format!(
        "System Swap Usage: {:.2}Gb/{:.2}Gb",
        sys_info.swap_used as f32 / 1024f32 / 1024f32 / 1024f32,
        sys_info.swap_total as f32 / 1024f32 / 1024f32 / 1024f32
    );
    let swap_usage_widget = draw_gauge(
        &swap_title,
        ((sys_info.swap_used as f32 / sys_info.swap_total as f32) * 100f32) as u16,
    );
    f.render_widget(swap_usage_widget, overview_chunks[5]);

    let logs_widget = draw_logs();
    f.render_widget(logs_widget, wrapper_chunks[1]);
}

fn draw_logs<'a>() -> TuiLoggerWidget<'a> {
    TuiLoggerWidget::default()
        .style_error(Style::default().fg(Color::Red))
        .style_debug(Style::default().fg(Color::Green))
        .style_warn(Style::default().fg(Color::Yellow))
        .style_trace(Style::default().fg(Color::Gray))
        .style_info(Style::default().fg(Color::Blue))
        .block(
            Block::default()
                .title("Logs")
                .border_style(Style::default().fg(Color::White).bg(Color::Black))
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White).bg(Color::Black))
}

fn draw_gauge(title: &str, value: u16) -> Gauge<'_> {
    let gauge = Gauge::default()
        .block(Block::default().title(title).borders(Borders::ALL))
        .percent(value);
    if value > 50 {
        gauge.gauge_style(Style::default().fg(Color::LightRed))
    } else if value > 80 {
        gauge.gauge_style(Style::default().fg(Color::LightYellow))
    } else {
        gauge.gauge_style(Style::default().fg(Color::LightGreen))
    }
}
