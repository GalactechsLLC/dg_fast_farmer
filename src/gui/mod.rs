use actix_web::web::Data;
use actix_web::{App, HttpServer};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ratatui::style::Stylize;
use ratatui::{prelude::*, widgets::*};

use tui_logger::*;

use crate::farmer::config::{load_keys, Config};
use crate::farmer::{ExtendedFarmerSharedState, Farmer, GuiStats};
use crate::metrics;
use crate::tasks::blockchain_state_updater::update_blockchain;
use crate::tasks::pool_state_updater::pool_updater;
use chrono::prelude::*;
use dg_xch_clients::api::pool::DefaultPoolClient;
use dg_xch_core::blockchain::blockchain_state::BlockchainState;
use dg_xch_core::protocols::farmer::FarmerSharedState;
use log::{error, LevelFilter};
use sysinfo::System;
use tokio::sync::Mutex;
use tokio::task::{spawn_blocking, JoinHandle};
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
struct SysInfo {
    cpu_usage: u16,
    ram_used: u64,
    ram_total: u64,
    swap_used: u64,
    swap_total: u64,
}

struct GuiState {
    system_info: Arc<Mutex<SysInfo>>,
    farmer_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
}

impl GuiState {
    fn new(shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>) -> GuiState {
        GuiState {
            system_info: Default::default(),
            farmer_state: shared_state,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FullNodeState {
    pub blockchain_state: BlockchainState,
}

pub async fn bootstrap(config: Arc<Config>) -> Result<(), Error> {
    init_logger(LevelFilter::Info).unwrap();
    set_default_level(LevelFilter::Info);
    enable_raw_mode()?;
    let (farmer_private_keys, owner_secret_keys, auth_secret_keys, pool_public_keys) =
        load_keys(config.clone()).await;
    let shared_state = Arc::new(FarmerSharedState {
        farmer_private_keys: Arc::new(farmer_private_keys),
        owner_secret_keys: Arc::new(owner_secret_keys),
        owner_public_keys_to_auth_secret_keys: Arc::new(auth_secret_keys),
        pool_public_keys: Arc::new(pool_public_keys),
        data: Arc::new(ExtendedFarmerSharedState {
            config: config.clone(),
            run: Arc::new(AtomicBool::new(true)),
            ..Default::default()
        }),
        ..Default::default()
    });
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let gui_state = Arc::new(GuiState::new(shared_state.clone()));
    let farmer_gui_state = gui_state.clone();
    let farmer_thread = tokio::spawn(async move {
        let farmer_state = farmer_gui_state.farmer_state.clone();
        let pool_state = farmer_state.clone();
        let pool_state_handle: JoinHandle<()> =
            tokio::spawn(async move { pool_updater(pool_state).await });
        let pool_client = Arc::new(DefaultPoolClient::new());
        let farmer = Farmer::new(farmer_state, pool_client).await?;
        let client_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
            farmer.run().await;
            Ok(())
        });
        let _ = join!(pool_state_handle, client_handle);
        Ok::<(), Error>(())
    });
    let fullnode_state = gui_state.clone();
    let fullnode_thread = tokio::spawn(async move {
        update_blockchain(config.clone(), fullnode_state.farmer_state.clone()).await
    });
    let sys_info_gui_state = gui_state.clone();
    let sys_info_thread = tokio::spawn(async move {
        let mut system = System::new();
        system.refresh_cpu();
        system.refresh_memory();
        sleep(Duration::from_secs(3)).await;
        system.refresh_cpu();
        system.refresh_memory();
        loop {
            let results = spawn_blocking(move || {
                system.refresh_cpu();
                system.refresh_memory();
                let si = SysInfo {
                    cpu_usage: system.global_cpu_info().cpu_usage() as u16,
                    ram_used: system.used_memory(),
                    ram_total: system.total_memory(),
                    swap_used: system.used_swap(),
                    swap_total: system.total_swap(),
                };
                (system, si)
            })
            .await;
            let (sys, sys_info) = results.unwrap_or_else(|e| {
                error!("Error Joining System Loading Thread: {:?}", e);
                (System::new(), Default::default())
            });
            *sys_info_gui_state.system_info.lock().await = sys_info;
            system = sys;
            if !sys_info_gui_state
                .farmer_state
                .data
                .run
                .load(Ordering::Relaxed)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    let metrics = shared_state.data.config.metrics.clone().unwrap_or_default();
    let metrics_state = shared_state.clone();
    let server_handle = if metrics.enabled {
        tokio::spawn(async move {
            let server_state = metrics_state.clone();
            select! {
                _ = HttpServer::new(move || {
                        App::new()
                            .app_data(Data::new(server_state.clone()))
                            .configure(metrics::init)
                    })
                    .bind(("0.0.0.0", metrics.port))?
                    .run()
                => {
                    Ok(())
                }
                _ = async {
                    loop {
                        if !metrics_state.data.run.load(Ordering::Relaxed) {
                            break;
                        }
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

async fn run_gui<B: Backend>(
    terminal: &mut Terminal<B>,
    gui_state: Arc<GuiState>,
) -> std::io::Result<()> {
    loop {
        {
            let farmer_state = gui_state.farmer_state.data.gui_stats.read().await.clone();
            let sys_info = *gui_state.system_info.lock().await;
            let fullnode_state = gui_state
                .farmer_state
                .data
                .fullnode_state
                .read()
                .await
                .clone();
            terminal.draw(|f| ui(f, farmer_state, fullnode_state, sys_info))?;
        }
        if event::poll(Duration::from_millis(25))? {
            if let Event::Key(event) = event::read()? {
                match event.code {
                    KeyCode::Esc => {
                        gui_state
                            .farmer_state
                            .data
                            .run
                            .store(false, Ordering::Relaxed);
                    }
                    KeyCode::Char('c') => {
                        if event.modifiers == KeyModifiers::CONTROL {
                            gui_state
                                .farmer_state
                                .data
                                .run
                                .store(false, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                }
            }
        }
        if !gui_state.farmer_state.data.run.load(Ordering::Relaxed) {
            break;
        }
    }
    Ok(())
}

fn ui(
    f: &mut Frame,
    farmer_state: GuiStats,
    fullnode_state: Option<FullNodeState>,
    sys_info: SysInfo,
) {
    let size = f.size();
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
            farmer_state.total_plot_count,
            bytefmt::format_to(farmer_state.total_plot_space, bytefmt::Unit::TIB),
            farmer_state.total_plot_space,
            farmer_state.most_recent_sp.0,
            farmer_state.most_recent_sp.1,
        )
    };

    let mut height: u32 = 0;
    let mut timestamp: u64 = 0;
    let mut sync: bool = false;
    let mut difficulty: u64 = 0;
    let mut space: u128 = 0;
    let mut mempool_size: u64 = 0;

    if let Some(full_node) = fullnode_state {
        if let Some(peak) = full_node.blockchain_state.peak {
            height = peak.height;
            if let Some(_timestamp) = peak.timestamp {
                timestamp = _timestamp;
            }
        }
        sync = full_node.blockchain_state.sync.synced;
        difficulty = full_node.blockchain_state.difficulty;
        space = full_node.blockchain_state.space;
        mempool_size = full_node.blockchain_state.mempool_size;
    }
    let formatted_timestamp: String = if timestamp != 0 {
        let datetime = DateTime::from_timestamp(timestamp as i64, 0).unwrap_or_default();
        datetime.format("%d-%m-%Y %H:%M:%S").to_string()
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

fn draw_gauge(title: &str, value: u16) -> Gauge {
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
