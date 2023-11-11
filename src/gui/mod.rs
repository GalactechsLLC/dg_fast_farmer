use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    },
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
            let sys_info = gui_state.system_info.lock().await.clone();
            let fullnode_state = gui_state.fullnode_state.lock().await.clone();
            terminal.draw(|f| ui(f, farmer_state, fullnode_state, sys_info))?;
        }
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(KeyEvent {
                    code, modifiers, ..
                }) => match code {
                    KeyCode::Esc => {
                        gui_state.farmer_state.run.store(false, Ordering::Relaxed);
                    }
                    KeyCode::Char('c') => {
                        if modifiers == KeyModifiers::CONTROL {
                            gui_state.farmer_state.run.store(false, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                },
                _ => {}
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
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(size);

    let block = Block::default().on_black().gray();
    f.render_widget(block, size);
    let title = Block::default().borders(Borders::ALL).title("Fast Farmer");
    f.render_widget(title, chunks[0]);

    let wrapper_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(chunks[1]);

    let overview_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage(32),
                Constraint::Percentage(20),
                Constraint::Percentage(31),
                Constraint::Percentage(6),
                Constraint::Percentage(6),
                Constraint::Percentage(5),
            ]
            .as_ref(),
        )
        .split(wrapper_chunks[0]);

    let farmer_info = {
        format!(
            "\t  Process State: Running\n\
             \t  Keys Farming: {:#?}\n\
             \t  Most Recent Signage Point: {:#?} [ {:#?} ]\n\
             \t  {:#?}\n",
            farmer_state.keys,
            farmer_state.most_recent_sp.1,
            farmer_state.most_recent_sp.0,
            farmer_state.recent_errors,
        )
    };

    let harvester_info = {
        format!(
            "\t  OG Plot Count: {:#?}\n\
             \t  NFT Plot Count: {:#?}\n\
             \t  Compressed Plot Count: {:#?}\n\
             \t  Invalid Plot Count: {:#?}\n\
             \t  Plot Space: {:#?} ({:#?})\n",
            farmer_state.og_plot_count,
            farmer_state.nft_plot_count,
            farmer_state.compressed_plot_count,
            farmer_state.invalid_plot_count,
            bytefmt::format_to(farmer_state.plot_space as u64, bytefmt::Unit::TIB),
            farmer_state.plot_space,
        )
    };

    let fullnode_info = { format!("\t   Blockchain State: {:#?}\n", fullnode_state,) };

    let farmer_content = Paragraph::new(farmer_info).block(
        Block::default()
            .title("Farmer Information: ")
            .borders(Borders::ALL),
    );
    f.render_widget(farmer_content, overview_chunks[0]);
    let harvester_content = Paragraph::new(harvester_info).block(
        Block::default()
            .title("Harvester Information: ")
            .borders(Borders::ALL),
    );
    f.render_widget(harvester_content, overview_chunks[1]);
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
