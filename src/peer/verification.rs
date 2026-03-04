pub fn sas_words(sas_bytes: &[u8; 12]) -> [String; 6] {
    let w0 = u16::from_be_bytes([sas_bytes[0], sas_bytes[1]]) as usize % WORDLIST.len();
    let w1 = u16::from_be_bytes([sas_bytes[2], sas_bytes[3]]) as usize % WORDLIST.len();
    let w2 = u16::from_be_bytes([sas_bytes[4], sas_bytes[5]]) as usize % WORDLIST.len();
    let w3 = u16::from_be_bytes([sas_bytes[6], sas_bytes[7]]) as usize % WORDLIST.len();
    let w4 = u16::from_be_bytes([sas_bytes[8], sas_bytes[9]]) as usize % WORDLIST.len();
    let w5 = u16::from_be_bytes([sas_bytes[10], sas_bytes[11]]) as usize % WORDLIST.len();

    [
        WORDLIST[w0].to_string(),
        WORDLIST[w1].to_string(),
        WORDLIST[w2].to_string(),
        WORDLIST[w3].to_string(),
        WORDLIST[w4].to_string(),
        WORDLIST[w5].to_string(),
    ]
}

pub fn format_sas(sas_bytes: &[u8; 12]) -> String {
    let words = sas_words(sas_bytes);
    words.join(" ")
}

const WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "action", "actor", "actual", "adapt", "address", "adjust", "admit", "adult",
    "advance", "advice", "aerobic", "affair", "afford", "agree", "ahead", "aim", "air", "airport",
    "aisle", "alarm", "album", "alert", "alien", "allow", "almost", "alpha", "already", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
    "antique", "anxiety", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "armor", "army", "arrange", "arrest", "arrive", "arrow",
    "artist", "asset", "assist", "assume", "atom", "attack", "attend", "auto", "autumn", "average",
    "avocado", "avoid", "awake", "aware", "bamboo", "banana", "banner", "barely", "barrel",
    "basic", "basket", "battle", "beach", "beauty", "become", "before", "begin", "behind",
    "believe", "below", "bench", "benefit", "beyond", "bicycle", "blanket", "blast", "bloom",
    "board", "bonus", "border", "bottle", "bounce", "brave", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "broad", "broken", "bronze", "brush", "bubble", "buddy", "budget",
    "buffalo", "build", "bullet", "bundle", "burden", "burger", "burst", "butter", "cabin",
    "cable", "cactus", "camera", "cancel", "canvas", "captain", "carbon", "cargo", "carpet",
    "casual", "catalog", "catch", "cause", "ceiling", "celery", "cement", "census", "chapter",
    "charge", "cherry", "chicken", "chief", "choice", "chunk", "circle", "citizen", "civil",
    "claim", "clap", "clarify", "claw", "clean", "clerk", "clever", "clinic", "clock", "close",
    "cloud", "clown", "cluster", "coach", "coconut", "coffee", "column", "combine", "comfort",
    "comic", "common", "company", "concert", "connect", "coral", "core", "cotton", "couch",
    "country", "couple", "course", "cousin", "craft", "crane", "crash", "crater", "credit",
    "cricket", "crisis", "crisp", "cross", "crucial", "cruel", "cruise", "crystal", "cube",
    "culture", "current", "curtain", "curve", "cushion", "custom", "cycle", "damage", "dance",
    "danger", "daring", "dash", "daughter", "dawn", "debate", "decade", "december", "decide",
    "decline", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand",
    "denial", "dentist", "deposit", "derive", "desert", "design", "detail",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_deterministic() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let w1 = sas_words(&bytes);
        let w2 = sas_words(&bytes);
        assert_eq!(w1, w2);
    }

    #[test]
    fn sas_different_bytes_different_words() {
        let b1 = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let b2 = [
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4,
        ];
        let w1 = sas_words(&b1);
        let w2 = sas_words(&b2);
        assert_ne!(w1, w2);
    }

    #[test]
    fn format_sas_readable() {
        let bytes = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
        ];
        let s = format_sas(&bytes);
        assert!(s.contains(' '));
        assert_eq!(s.split_whitespace().count(), 6);
    }

    #[test]
    fn wordlist_size() {
        assert_eq!(WORDLIST.len(), 256);
    }

    #[test]
    fn all_words_non_empty() {
        for word in WORDLIST {
            assert!(!word.is_empty());
        }
    }
}
