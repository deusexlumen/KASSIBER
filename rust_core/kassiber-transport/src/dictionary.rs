//! Word dictionary for the transport codec.
//!
//! The built-in dictionary is the official BIP-39 English wordlist: exactly
//! 2048 unique words, i.e. 11 bits per word (`log2(2048) = 11`).

use crate::error::TransportError;

#[path = "dictionary/bip39_english.rs"]
mod bip39_english;

pub type Result<T> = std::result::Result<T, TransportError>;

pub trait WordDictionary: Send + Sync {
    fn word_at(&self, index: u16) -> Result<&str>;
    fn index_of(&self, word: &str) -> Result<u16>;
    fn size(&self) -> u16;
    /// Bits encoded per word: `log2(size)`. For the 2048-word BIP-39 list
    /// this is 11.
    fn bits_per_word(&self) -> u8 {
        self.size().trailing_zeros() as u8
    }
}

#[derive(Debug, Clone)]
pub struct Bip39Dictionary {
    words: Vec<String>,
    index_map: std::collections::HashMap<String, u16>,
}

impl Bip39Dictionary {
    /// Build a dictionary from a custom word list. The list MUST contain
    /// exactly 2048 unique words.
    pub fn new(word_list: Vec<String>) -> Result<Self> {
        if word_list.len() != 2048 {
            return Err(TransportError::InvalidDictionary(format!(
                "Expected 2048 words, got {}",
                word_list.len()
            )));
        }
        let mut index_map = std::collections::HashMap::with_capacity(2048);
        for (i, word) in word_list.iter().enumerate() {
            if index_map.insert(word.to_lowercase(), i as u16).is_some() {
                return Err(TransportError::InvalidDictionary(format!(
                    "Duplicate word: {}",
                    word
                )));
            }
        }
        Ok(Self {
            words: word_list,
            index_map,
        })
    }

    /// The official BIP-39 English wordlist (2048 words, 11 bits/word).
    pub fn english() -> Self {
        Self::new(
            bip39_english::BIP39_ENGLISH_WORDS
                .iter()
                .map(|&w| w.to_string())
                .collect(),
        )
        .expect("the embedded BIP-39 wordlist is exactly 2048 unique words")
    }

    pub fn to_natural_sentence(&self, encoded: &[u16]) -> String {
        if encoded.is_empty() {
            return String::new();
        }
        let words: Vec<&str> = encoded
            .iter()
            .map(|&idx| self.words[idx as usize].as_str())
            .collect();
        let sentence_lengths = [6usize, 8, 10, 12];
        let mut sentences = Vec::new();
        let mut pos = 0;
        let mut len_idx = 0;
        while pos < words.len() {
            let len = sentence_lengths[len_idx % sentence_lengths.len()].min(words.len() - pos);
            sentences.push(words[pos..pos + len].join(" "));
            pos += len;
            len_idx += 1;
        }
        sentences.join(". ") + "."
    }

    /// Decode a sentence back into word indices.
    ///
    /// Unknown words are a hard error — silently dropping them (the old
    /// `filter_map` behaviour) corrupts the payload without any signal.
    pub fn from_natural_sentence(&self, sentence: &str) -> Result<Vec<u16>> {
        let cleaned = sentence
            .to_lowercase()
            .replace(|c: char| c == '.' || c == ',' || c == '!' || c == '?', " ");
        cleaned
            .split_whitespace()
            .map(|word| {
                self.index_map
                    .get(word)
                    .copied()
                    .ok_or_else(|| TransportError::UnknownWord(word.to_string()))
            })
            .collect()
    }
}

impl WordDictionary for Bip39Dictionary {
    fn word_at(&self, index: u16) -> Result<&str> {
        self.words
            .get(index as usize)
            .map(|s| s.as_str())
            .ok_or(TransportError::InvalidIndex(index))
    }
    fn index_of(&self, word: &str) -> Result<u16> {
        self.index_map
            .get(word)
            .copied()
            .ok_or_else(|| TransportError::UnknownWord(word.to_string()))
    }
    fn size(&self) -> u16 {
        2048
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_english_list_is_real_bip39() {
        let dict = Bip39Dictionary::english();
        assert_eq!(dict.words.len(), 2048);
        // BIP-39 anchors: first and last word, sorted order.
        assert_eq!(dict.word_at(0).unwrap(), "abandon");
        assert_eq!(dict.word_at(2047).unwrap(), "zoo");
        let mut sorted = dict.words.clone();
        sorted.sort();
        assert_eq!(dict.words, sorted);
        // All unique (HashMap insert would have collapsed duplicates).
        assert_eq!(dict.index_map.len(), 2048);
    }

    #[test]
    fn test_bits_per_word_is_11() {
        let dict = Bip39Dictionary::english();
        assert_eq!(dict.bits_per_word(), 11);
    }

    #[test]
    fn test_unknown_word_is_an_error() {
        let dict = Bip39Dictionary::english();
        assert!(dict.from_natural_sentence("abandon nosuchword zoo").is_err());
        let ok = dict.from_natural_sentence("Abandon, ability. Zoo!").unwrap();
        assert_eq!(ok, vec![0, 1, 2047]);
    }
}
