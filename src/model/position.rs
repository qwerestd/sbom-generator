use std::num::NonZeroU32;

use bstr::BStr;
use bstr::ByteSlice;
use derive_builder::Builder;

#[derive(Builder, Clone, Copy, Debug)]
pub struct Position {
    #[allow(dead_code)]
    pub line: NonZeroU32,
    #[allow(dead_code)]
    pub col: NonZeroU32,
}

impl Default for Position {
    fn default() -> Self {
        Self {
            line: NonZeroU32::new(1).unwrap(),
            col: NonZeroU32::new(1).unwrap(),
        }
    }
}

/// Get position of an offset in a code and return a [Position].
pub fn get_position_in_string(content: &str, offset: usize) -> anyhow::Result<Position> {
    if offset >= content.len() {
        anyhow::bail!("offset is larger than content length");
    }

    let bstr = BStr::new(content);
    let lines = bstr.lines_with_terminator();

    // 追踪当前行在整个字符串中的起始字节偏移量
    let mut current_line_offset = 0;

    // 修复点 1: 使用 (1_u32..) 和 zip 消除外层行计数器 line_number
    for (line_number, line) in (1_u32..).zip(lines) {
        let start_index = current_line_offset;
        let end_index = start_index + line.len();

        if (start_index..end_index).contains(&offset) {
            // 修复点 2: 使用 (1_u32..) 和 zip 消除内层列计数器 col_number
            for (col_number, (grapheme_start, grapheme_end, _)) in
                (1_u32..).zip(line.grapheme_indices())
            {
                let grapheme_absolute_start = start_index + grapheme_start;
                let grapheme_absolute_end = start_index + grapheme_end;

                // It's exactly the index we are looking for.
                if offset == grapheme_absolute_start {
                    return Ok(Position {
                        line: NonZeroU32::new(line_number).unwrap(),
                        col: NonZeroU32::new(col_number).unwrap(),
                    });
                }

                // The offset is within the grapheme we are looking for, it's the next col.
                if (grapheme_absolute_start..grapheme_absolute_end).contains(&offset) {
                    return Ok(Position {
                        line: NonZeroU32::new(line_number).unwrap(),
                        col: NonZeroU32::new(col_number + 1).unwrap(),
                    });
                }
            }
        }

        // 累加当前行的长度，作为下一行的起始偏移量
        current_line_offset += line.len();
    }

    Err(anyhow::anyhow!("cannot find position"))
}
