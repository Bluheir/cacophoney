use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use event::KeyCode;

use std::{
    error::Error,
    io,
    ops::DerefMut,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::{Receiver, Sender};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, Paragraph, Widget},
    Frame, Terminal,
};

pub enum ActionExecution {
    Select(String),
    Input(String),
}
#[derive(Debug)]
pub enum InputType {
    Password,
    Text,
}
#[derive(Debug)]
pub enum InputChangeReq {
    Command,
    Options(SelectOption),
    Input(String, InputType),
}
#[derive(Default, Debug)]
pub struct SelectOption {
    pub title: String,
    pub current: usize,
    pub options: Vec<String>,
}
#[derive(Default)]
pub struct AppState {
    pub select: Selected,
    pub mode: InputMode,
    pub selected_input: u16,
    pub offset: u16,
    pub log_msgs: Vec<Vec<(String, Style)>>,
}
pub enum Selected {
    Input,
    Logs,
}
impl Default for Selected {
    fn default() -> Self {
        Selected::Input
    }
}
pub enum InputMode {
    None,
    Options(SelectOption),
    Input(String, Vec<char>, InputType),
}
impl Default for InputMode {
    fn default() -> Self {
        Self::None
    }
}

pub fn render_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    ini_app: AppState,
    send: Sender<ActionExecution>,
    recv: Receiver<InputChangeReq>,
    log_recv: Receiver<Vec<(String, Style)>>,
) -> io::Result<()> {
    let app = Arc::new(RwLock::new(ini_app));
    let c = app.clone();
    let d = app.clone();

    thread::spawn(move || msg_loop(c, recv));
    thread::spawn(move || log_loop(d, log_recv));

    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(100);

    loop {
        let lock_app = app.read().unwrap();
        terminal.draw(|f| ui2(f, &lock_app))?;
        drop(lock_app);

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            let mut b = app.write().unwrap();
            let w_app = b.deref_mut();

            let event = event::read()?;

            if let Event::Key(key) = event {
                match &w_app.select {
                    Selected::Input => match key.code {
                        KeyCode::Tab => w_app.select = Selected::Logs,
                        KeyCode::Esc => {
                            drop(b);
                            return Ok(());
                        }
                        _ => {
                            match &mut w_app.mode {
                                InputMode::None => {}
                                InputMode::Options(options) => match key.code {
                                    KeyCode::Up => {
                                        if options.current != 0 {
                                            // Move up
                                            options.current -= 1;
                                        } else {
                                            // Go around in a circle
                                            options.current = options.options.len() - 1;
                                        }
                                    }
                                    KeyCode::Down => {
                                        if options.current == options.options.len() - 1 {
                                            // Go around in a circle
                                            options.current = 0;
                                        } else {
                                            // Move down
                                            options.current += 1;
                                        }
                                    }
                                    KeyCode::Enter => {
                                        let _ = send.blocking_send(ActionExecution::Select(
                                            options.options[options.current].clone(),
                                        ));
                                        // Reset input
                                        w_app.mode = InputMode::None;
                                        w_app.offset = 0;
                                    }
                                    _ => {}
                                },
                                InputMode::Input(_, chars, _) => match key.code {
                                    KeyCode::Left => {
                                        if w_app.offset != 0 {
                                            // Move cursor to the left
                                            w_app.offset -= 1
                                        }
                                    }
                                    KeyCode::Right => {
                                        if w_app.offset as usize != chars.len() {
                                            // Move cursor to the right
                                            w_app.offset += 1
                                        }
                                    }
                                    KeyCode::Backspace => {
                                        if w_app.offset != 0 {
                                            if w_app.offset as usize == chars.len() {
                                                // Move cursor to the left and remove last char
                                                w_app.offset -= 1;
                                                chars.remove((w_app.offset) as usize);
                                            } else {
                                                // Move cursor to the left and remove char before cursor
                                                chars.remove((w_app.offset - 1) as usize);
                                                w_app.offset -= 1;
                                            }
                                        }
                                    }
                                    KeyCode::Char(c) => {
                                        // Insert the char and move the cursor to the right
                                        chars.insert(w_app.offset as usize, c);
                                        w_app.offset += 1;
                                    }
                                    KeyCode::Enter => {
                                        let _ = send.blocking_send(ActionExecution::Input(
                                            chars.iter().collect::<String>(),
                                        ));
                                        // Reset input
                                        w_app.mode = InputMode::None;
                                        w_app.offset = 0;
                                    }
                                    _ => {}
                                },
                            }
                        }
                    },
                    Selected::Logs => match key.code {
                        KeyCode::Tab => w_app.select = Selected::Input,
                        KeyCode::Esc => {
                            drop(b);
                            return Ok(());
                        }
                        _ => {}
                    },
                }
            }

            if let Event::Paste(value) = event {
                match &w_app.select {
                    Selected::Input => match &mut w_app.mode {
                        InputMode::Input(_, chars, _) => {
                            let value = value.chars().collect::<Vec<char>>();
                            let len = value.len();

                            // Reserve the chars.len() in the vector
                            chars.reserve(len);

                            chars.splice((w_app.offset as usize)..(w_app.offset as usize), value);
                            w_app.offset += len as u16;
                        }
                        _ => {}
                    },
                    Selected::Logs => todo!(),
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}
fn log_loop(app: Arc<RwLock<AppState>>, mut recv: Receiver<Vec<(String, Style)>>) {
    while let Some(t) = recv.blocking_recv() {
        let mut w = app.write().unwrap();

        w.log_msgs.push(t);
    }
}
fn msg_loop(app: Arc<RwLock<AppState>>, mut recv: Receiver<InputChangeReq>) {
    while let Some(t) = recv.blocking_recv() {
        let mut w = app.write().unwrap();
        w.offset = 0;

        match t {
            InputChangeReq::Command => todo!(),
            InputChangeReq::Options(v) => w.mode = InputMode::Options(v),
            InputChangeReq::Input(s, input_type) => {
                w.mode = InputMode::Input(s, Vec::new(), input_type);
            }
        }
        drop(w);
    }
}

fn ui2<B: Backend>(f: &mut Frame<B>, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .vertical_margin(1)
        .constraints([Constraint::Min(1), Constraint::Length(8)].as_ref())
        .split(f.size());

    let (input_fg, log_fg) = match &app.select {
        Selected::Input => (Color::Yellow, Color::White),
        Selected::Logs => (Color::White, Color::Yellow),
    };

    let log_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(log_fg))
        .title("Logs");

    let mut p = Paragraph::new(
        app.log_msgs
            .iter()
            .map(|a| {
                Spans::from(
                    a.iter()
                        .map(|b| Span::styled(b.0.clone(), b.1))
                        .collect::<Vec<Span>>(),
                )
            })
            .collect::<Vec<Spans>>(),
    )
    .block(log_block);

    f.render_widget(p, chunks[0]);

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(input_fg))
        .title("Input");

    let mut p: Paragraph;

    match &app.mode {
        InputMode::None => {
            let spans: Vec<Spans> = vec![];
            p = Paragraph::new(spans);
        }
        InputMode::Options(v) => {
            let mut spans = Vec::<Spans>::with_capacity(v.options.len() + 1);
            spans.push(Spans::from(vec![Span::styled(
                format!("      {}", v.title),
                Style::default().add_modifier(Modifier::BOLD),
            )]));
            spans.push(Spans::from(vec![Span::raw("")]));

            for (i, o) in v.options.iter().enumerate() {
                let mut base = "      ".chars().collect::<Vec<char>>();

                if i == v.current {
                    base.extend(format!(" > {}", o).chars());
                    spans.push(Spans::from(rainbowify(&base)))
                } else {
                    base.extend(format!("> {}", o).chars());
                    spans.push(Spans::from(vec![Span::raw(
                        base.iter().collect::<String>(),
                    )]));
                }
            }

            p = Paragraph::new(spans);
        }
        InputMode::Input(title, value, input_type) => {
            let mut text = Vec::new();
            text.push(Span::raw("      > "));

            match input_type {
                InputType::Text => {
                    text.extend(rainbowify(value));
                    match &app.select {
                        Selected::Input => {
                            f.set_cursor(chunks[1].x + app.offset + 9, chunks[1].y + 3)
                        }
                        _ => {}
                    }
                }
                InputType::Password => {
                    text.push(Span::styled(
                        "*",
                        Style::default()
                            .bg(input_fg)
                            .fg(log_fg)
                            .add_modifier(Modifier::RAPID_BLINK),
                    ));
                }
            }

            let spans = vec![
                Spans::from(vec![Span::styled(
                    format!("      {}", title),
                    Style::default().add_modifier(Modifier::BOLD),
                )]),
                Spans::from(vec![Span::raw("")]),
                Spans::from(text),
            ];

            p = Paragraph::new(spans);
        }
    }

    p = p.block(input_block);

    f.render_widget(p, chunks[1])
}

fn rainbowify<'a>(s: &Vec<char>) -> Vec<Span<'a>> {
    let colors = [
        Color::Red,
        Color::LightRed,
        Color::Rgb(201, 70, 18),
        Color::Yellow,
        Color::LightYellow,
        Color::LightCyan,
        Color::Cyan,
        Color::LightBlue,
        Color::Blue,
        Color::Magenta,
        Color::LightMagenta,
        Color::LightGreen,
        Color::Green,
    ];
    //colors.shuffle(&mut OsRng);

    s.iter()
        .enumerate()
        .map(|(i, c)| {
            Span::styled(
                c.to_string(),
                Style::default().fg(colors[(i as f64 / 0.9f64).round() as usize % colors.len()]),
            )
        })
        .collect::<Vec<Span>>()
}

pub fn terminal_init(
    send: Sender<ActionExecution>,
    recv: Receiver<InputChangeReq>,
    log_recv: Receiver<Vec<(String, Style)>>,
) -> Result<(), Box<dyn Error>> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let app = AppState::default();
    let res = render_loop(&mut terminal, app, send, recv, log_recv);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}
