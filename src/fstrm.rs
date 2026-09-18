use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::{info, trace, warn};
use std::{
    cmp::min,
    collections::HashSet,
    convert::TryInto,
    io::{self, ErrorKind, Read, Result, Write},
    iter::FromIterator,
    marker::PhantomData,
};

// Constants copy from `fstrm/control.h`
const CONTROL_FRAME_LENGTH_MAX: usize = 512;
const CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX: usize = 256;

const CONTROL_TYPE_ACCEPT: u32 = 0x01;
const CONTROL_TYPE_START: u32 = 0x02;
const CONTROL_TYPE_STOP: u32 = 0x03;
const CONTROL_TYPE_READY: u32 = 0x04;
const CONTROL_TYPE_FINISH: u32 = 0x05;

const CONTROL_FIELD_CONTENT_TYPE: u32 = 0x01;

pub mod states {
    pub struct Ready;
    pub struct Accepted;
    pub struct Started;

    pub trait BeforeStart {}
    impl BeforeStart for Ready {}
    impl BeforeStart for Accepted {}

    pub trait AfterReady {}
    impl AfterReady for Accepted {}
    impl AfterReady for Started {}
}

pub struct FstrmReader<R, S> {
    reader: R,
    state: PhantomData<S>,
    content_types: HashSet<String>,
}

impl<R, S> FstrmReader<R, S> {
    /// Create a new reader that accpets all content types.
    pub fn new(reader: R) -> FstrmReader<R, states::Ready> {
        FstrmReader {
            reader,
            state: PhantomData,
            content_types: HashSet::new(),
        }
    }

    /// Create a new reader that accepts only given set of content types.
    pub fn allow_content_types<T>(
        reader: R,
        allowed_content_types: T,
    ) -> FstrmReader<R, states::Ready>
    where
        T: IntoIterator<Item = String>,
    {
        FstrmReader {
            reader,
            state: PhantomData,
            content_types: HashSet::from_iter(allowed_content_types),
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

fn intersect_content_types(
    src: HashSet<String>,
    types: HashSet<String>,
) -> Result<HashSet<String>> {
    let set = if src.is_empty() {
        types
    } else {
        HashSet::from_iter(src.intersection(&types).cloned())
    };
    if set.is_empty() {
        Err(io::Error::new(
            ErrorKind::InvalidData,
            "content types mismatched",
        ))
    } else {
        Ok(set)
    }
}

impl<R: Read, S: states::BeforeStart> FstrmReader<R, S> {
    /// Read the START frame.
    pub fn start(mut self) -> Result<FstrmReader<R, states::Started>> {
        let frame = self.read_control_frame()?;
        frame.assert_type(ControlType::Start)?;
        let types = frame.content_types();
        let content_types = intersect_content_types(self.content_types, types)?;
        Ok(FstrmReader {
            reader: self.reader,
            state: PhantomData,
            content_types,
        })
    }
}

impl<R: Read + Write> FstrmReader<R, states::Ready> {
    /// Read the READY frame then reply with ACCEPT.
    pub fn accept(mut self) -> Result<FstrmReader<R, states::Accepted>> {
        let frame = self.read_control_frame()?;
        frame.assert_type(ControlType::Ready)?;
        let types = frame.content_types();
        let content_types = intersect_content_types(self.content_types, types)?;

        let mut buf = Vec::with_capacity(12);
        buf.write_u32::<BigEndian>(CONTROL_TYPE_ACCEPT)?;
        for typ in content_types.iter() {
            buf.write_u32::<BigEndian>(CONTROL_FIELD_CONTENT_TYPE)?;
            buf.write_u32::<BigEndian>(typ.len() as u32)?;
            buf.write_all(typ.as_bytes())?;
        }
        self.reader.write_u32::<BigEndian>(0)?; // escape
        self.reader.write_u32::<BigEndian>(buf.len() as u32)?;
        self.reader.write_all(&buf)?;

        Ok(FstrmReader {
            reader: self.reader,
            state: PhantomData,
            content_types,
        })
    }
}

impl<R: Read + Write, S: states::AfterReady> FstrmReader<R, S> {
    /// Write FINISH frame to sender, return the inner reader.
    pub fn finish(mut self) -> Result<R> {
        self.reader.write_u32::<BigEndian>(0)?; // escape
        self.reader.write_u32::<BigEndian>(4)?; // length
        self.reader.write_u32::<BigEndian>(CONTROL_TYPE_FINISH)?;
        Ok(self.reader)
    }
}

#[derive(Debug, PartialEq)]
enum ControlType {
    Accept,
    Start,
    Stop,
    Ready,
    Finish,
    Unknown(u32),
}

enum FrameHeader {
    Data { size: usize },
    Control { size: usize, typ: ControlType },
}

impl From<u32> for ControlType {
    fn from(value: u32) -> Self {
        match value {
            CONTROL_TYPE_ACCEPT => ControlType::Accept,
            CONTROL_TYPE_START => ControlType::Start,
            CONTROL_TYPE_STOP => ControlType::Stop,
            CONTROL_TYPE_READY => ControlType::Ready,
            CONTROL_TYPE_FINISH => ControlType::Finish,
            _ => ControlType::Unknown(value),
        }
    }
}

impl<R: Read, S> FstrmReader<R, S> {
    fn next_length(&mut self) -> Result<usize> {
        Ok(self.reader.read_u32::<BigEndian>()?.try_into().unwrap())
    }

    fn read_frame_header(&mut self) -> Result<FrameHeader> {
        let size = self.next_length()?;
        if size > 0 {
            trace!("data frame ({} bytes)", size);
            Ok(FrameHeader::Data { size })
        } else {
            let size = self.next_length()?;
            if size > CONTROL_FRAME_LENGTH_MAX {
                Err(io::Error::other("control frame too large"))
            } else if size < 4 {
                Err(io::Error::other("control frame too small"))
            } else {
                let typ = self.reader.read_u32::<BigEndian>()?.into();
                trace!("control frame {:?} ({} bytes)", typ, size);
                Ok(FrameHeader::Control {
                    size: size - 4,
                    typ,
                })
            }
        }
    }

    fn read_control_frame(&mut self) -> Result<ControlFrame> {
        let (typ, size) = match self.read_frame_header()? {
            FrameHeader::Data { .. } => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "unexpected data frame",
                ))
            }
            FrameHeader::Control { typ, size } => (typ, size),
        };
        let mut frame = vec![0u8; size];
        self.reader.read_exact(&mut frame)?;

        let mut buf = &frame[..];
        let mut fields: Vec<ControlFrameField> = vec![];
        while !buf.is_empty() {
            let field_type = buf.read_u32::<BigEndian>()?;
            let size = buf.read_u32::<BigEndian>()? as usize;
            if size > buf.len() || size > CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX {
                warn!("paring error: control field too long");
                return Err(ErrorKind::UnexpectedEof.into());
            }
            let (field_content, remaining) = buf.split_at(size);
            buf = remaining;
            let field = match field_type {
                CONTROL_FIELD_CONTENT_TYPE => {
                    let typ = String::from_utf8(field_content.to_vec()).map_err(|_| {
                        io::Error::new(ErrorKind::InvalidData, "content type with invalid utf-8")
                    })?;
                    ControlFrameField::ContentType(typ)
                }
                typ => {
                    info!("unknown control field: {}", field_type);
                    ControlFrameField::Unknown(typ)
                }
            };
            fields.push(field);
        }
        Ok(ControlFrame { typ, fields })
    }
}

impl<R> FstrmReader<R, states::Started> {
    /// Negotiated content types
    pub fn content_types(&self) -> &HashSet<String> {
        &self.content_types
    }
}

impl<R: Read> FstrmReader<R, states::Started> {
    /// Read the next data frame, return None if the other side
    /// stop sending with a control frame.
    pub fn read_frame(&mut self) -> Result<Option<DataFrame<'_, R>>> {
        match self.read_frame_header()? {
            FrameHeader::Data { size } => Ok(Some(DataFrame::new(&mut self.reader, size))),
            FrameHeader::Control {
                typ: ControlType::Stop,
                ..
            } => Ok(None),
            FrameHeader::Control { typ, .. } => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unexpected control frame {:?}", typ),
            )),
        }
    }
}

pub enum ControlFrameField {
    ContentType(String),
    Unknown(u32),
}

pub struct ControlFrame {
    typ: ControlType,
    fields: Vec<ControlFrameField>,
}

impl ControlFrame {
    fn assert_type(&self, typ: ControlType) -> Result<()> {
        if self.typ == typ {
            Ok(())
        } else {
            Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("expect frame {:?} but {:?} received", typ, self.typ),
            ))
        }
    }

    fn content_types(self) -> HashSet<String> {
        self.fields
            .into_iter()
            .filter_map(|field| match field {
                ControlFrameField::ContentType(typ) => Some(typ),
                _ => None,
            })
            .collect()
    }
}

pub struct DataFrame<'a, R> {
    reader: &'a mut R,
    size: usize,
    pos: usize,
}

impl<'a, R> DataFrame<'a, R> {
    fn new(reader: &'a mut R, size: usize) -> Self {
        Self {
            reader,
            size,
            pos: 0,
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn remaining(&self) -> usize {
        self.size - self.pos
    }
}

impl<'a, R: Read> Read for DataFrame<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let max_len = min(buf.len(), self.remaining());
        let n = self.reader.read(&mut buf[..max_len])?;
        self.pos += n;
        if n == 0 && self.remaining() != 0 {
            Err(ErrorKind::UnexpectedEof.into())
        } else {
            Ok(n)
        }
    }
}

#[test]
fn test_unidirectional_reader() {
    let bytes: [u8; 65] = [
        0, 0, 0, 0, 0, 0, 0, 29, // control frame, length 29
        0, 0, 0, 2, // control type: START
        0, 0, 0, 1, // field type: content type
        0, 0, 0, 17, // field length 17
        116, 101, 115, 116, 45, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112,
        101, // "test-content-type"
        0, 0, 0, 12, // data frame, length 12
        116, 101, 115, 116, 45, 99, 111, 110, 116, 101, 110, 116, // "test-content"
        0, 0, 0, 0, 0, 0, 0, 4, // control frame, length 4
        0, 0, 0, 3, // control type: STOP
    ];

    let reader = FstrmReader::<_, ()>::new(&bytes[..]);
    let mut reader = reader.start().unwrap();
    let types = reader.content_types();
    assert_eq!(types.len(), 1);
    assert!(types.contains("test-content-type"));

    let mut frame = reader.read_frame().unwrap().unwrap();
    let mut buf = String::new();
    frame.read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "test-content");

    assert!(reader.read_frame().unwrap().is_none());
}
