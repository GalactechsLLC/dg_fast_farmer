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
use crate::farmer::{Farmer, FarmerSharedState, GuiStats};
use crate::tasks::pool_state_updater::pool_updater;
use chrono::prelude::*;
use dg_xch_clients::api::full_node::FullnodeAPI;
use dg_xch_clients::api::pool::DefaultPoolClient;
use dg_xch_clients::rpc::full_node::FullnodeClient;
use dg_xch_core::blockchain::blockchain_state::BlockchainState;
use dg_xch_keys::decode_puzzle_hash;
use log::{error, LevelFilter};
use sysinfo::{CpuExt, System, SystemExt};
use tokio::join;
use tokio::sync::Mutex;
use tokio::task::{spawn_blocking, JoinHandle};
use tokio::time::sleep;

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
    ram_usage: u16,
    swap_usage: u16,
}

struct GuiState {
    system_info: Arc<Mutex<SysInfo>>,
    farmer_state: Arc<FarmerSharedState>,
    fullnode_state: Arc<Mutex<Option<FullNodeState>>>,
}

impl GuiState {
    fn new(shared_state: Arc<FarmerSharedState>) -> GuiState {
        GuiState {
            system_info: Default::default(),
            farmer_state: shared_state,
            fullnode_state: Arc::new(Mutex::new(None)),
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
    let farmer_target_encoded = &config.payout_address;
    let farmer_target = decode_puzzle_hash(farmer_target_encoded)?;
    let pool_target = decode_puzzle_hash(farmer_target_encoded)?;
    let shared_state = Arc::new(FarmerSharedState {
        config: config.clone(),
        run: Arc::new(AtomicBool::new(true)),
        farmer_private_keys: Arc::new(farmer_private_keys),
        owner_secret_keys: Arc::new(owner_secret_keys),
        auth_secret_keys: Arc::new(auth_secret_keys),
        pool_public_keys: Arc::new(pool_public_keys),
        farmer_target: Arc::new(farmer_target),
        pool_target: Arc::new(pool_target),
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
        let full_node_rpc = FullnodeClient::new(
            &config.fullnode_host,
            config.fullnode_port,
            config.ssl_root_path.clone(),
            &None,
        );
        loop {
            let bc_state = full_node_rpc.get_blockchain_state().await;
            match bc_state {
                Ok(bc_state) => {
                    *fullnode_state.fullnode_state.lock().await = Some(FullNodeState {
                        blockchain_state: bc_state,
                    });
                }
                Err(e) => {
                    error!("{:?}", e);
                }
            }
            if !fullnode_state.farmer_state.run.load(Ordering::Relaxed) {
                break;
            }
            sleep(Duration::from_secs(5)).await;
        }
    });
    let sys_info_gui_state = gui_state.clone();
    let sys_info_thread = tokio::spawn(async move {
        let mut system = System::new();
        system.refresh_system();
        sleep(Duration::from_secs(3)).await;
        system.refresh_system();
        loop {
            let (sys, sys_info) = match spawn_blocking(move || {
                system.refresh_system();
                let si = SysInfo {
                    cpu_usage: system.global_cpu_info().cpu_usage() as u16,
                    ram_usage: ((system.used_memory() as f32 / system.total_memory() as f32)
                        * 100.0) as u16,
                    swap_usage: ((system.used_swap() as f32 / system.total_swap() as f32) * 100.0)
                        as u16,
                };
                (system, si)
            })
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!("Error Joining System Loading Thread: {:?}", e);
                    (System::new(), Default::default())
                }
            };
            *sys_info_gui_state.system_info.lock().await = sys_info;
            system = sys;
            if !sys_info_gui_state.farmer_state.run.load(Ordering::Relaxed) {
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
    });
    let (fn_res, sys_res, gui_res, farmer_res) = join!(
        fullnode_thread,
        sys_info_thread,
        run_gui(&mut terminal, gui_state),
        farmer_thread
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
    Ok(())
}

async fn run_gui<B: Backend>(
    terminal: &mut Terminal<B>,
    gui_state: Arc<GuiState>,
) -> std::io::Result<()> {
    loop {
        {
            let farmer_state = gui_state.farmer_state.gui_stats.lock().await.clone();
            let sys_info = *gui_state.system_info.lock().await;
            let fullnode_state = gui_state.fullnode_state.lock().await.clone();
            terminal.draw(|f| ui(f, farmer_state, fullnode_state, sys_info))?;
        }
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(event) = event::read()? {
                match event.code {
                    KeyCode::Esc => {
                        gui_state.farmer_state.run.store(false, Ordering::Relaxed);
                    }
                    KeyCode::Char('c') => {
                        if event.modifiers == KeyModifiers::CONTROL {
                            gui_state.farmer_state.run.store(false, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                }
            }
        }
        if !gui_state.farmer_state.run.load(Ordering::Relaxed) {
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
                Constraint::Percentage(35),
                Constraint::Percentage(40),
                Constraint::Percentage(5),
                Constraint::Percentage(5),
                Constraint::Percentage(5),
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
        let naive = NaiveDateTime::from_timestamp_opt(timestamp as i64, 0);
        let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive.unwrap_or_default(), Utc);
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
    let cpu_usage_widget = draw_cpu_usage(sys_info.cpu_usage);
    f.render_widget(cpu_usage_widget, overview_chunks[3]);
    let ram_usage_widget = draw_ram_usage(sys_info.ram_usage);
    f.render_widget(ram_usage_widget, overview_chunks[4]);
    let swap_usage_widget = draw_swap_usage(sys_info.swap_usage);
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

fn draw_cpu_usage<'a>(total_cpu_usage: u16) -> Gauge<'a> {
    let gauge = Gauge::default()
        .block(Block::default().title("CPU Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::LightGreen))
        .percent(total_cpu_usage);
    gauge
}

fn draw_ram_usage<'a>(total_ram_usage: u16) -> Gauge<'a> {
    let gauge = Gauge::default()
        .block(Block::default().title("RAM Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::LightBlue))
        .percent(total_ram_usage);
    gauge
}

fn draw_swap_usage<'a>(total_swap_usage: u16) -> Gauge<'a> {
    let gauge = Gauge::default()
        .block(Block::default().title("Swap Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::LightYellow))
        .percent(total_swap_usage);
    gauge
}
