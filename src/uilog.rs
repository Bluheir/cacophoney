use log::{Level, Metadata, Record};
use tokio::{runtime::Handle, sync::mpsc::Sender};
use tui::{
    style::{Color, Style},
    text::{Span, Spans},
};

pub struct Logger {
    sender: Sender<Vec<(String, Style)>>,
}

impl Logger {
    pub fn new(sender: Sender<Vec<(String, Style)>>) -> Self {
        Self { sender }
    }
}

fn format(record: &Record) -> Vec<(String, Style)> {
    let mut ret = Vec::new();

    let left_bracket = ("[".to_string(), Style::default());
    let time = (
        format!("{:?} ", chrono::offset::Local::now()),
        Style::default().fg(Color::Green),
    );
    let severity = (
        record.level().to_string(),
        match record.level() {
            Level::Error => Style::default().fg(Color::Red),
            Level::Warn => Style::default().fg(Color::Yellow),
            Level::Info => Style::default().fg(Color::Gray),
            Level::Debug => Style::default().fg(Color::LightGreen),
            Level::Trace => Style::default().fg(Color::LightCyan),
        },
    );
    let file = (
        match record.file() {
            Some(v) => format!(" {}", v),
            None => String::new(),
        },
        Style::default().fg(Color::Black),
    );
    let right_bracket = ("] ".to_string(), Style::default());
    let content = (record.args().to_string(), Style::default().fg(Color::White));

    ret.push(left_bracket);
    ret.push(time);
    ret.push(severity);
    ret.push(file);
    ret.push(right_bracket);
    ret.push(content);

    ret
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let handle = Handle::current();
            handle.enter();
            futures::executor::block_on(self.sender.send(format(record)));
        }
    }

    fn flush(&self) {}
}
