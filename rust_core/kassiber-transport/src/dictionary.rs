use crate::error::TransportError;
pub type Result<T> = std::result::Result<T, TransportError>;

pub trait WordDictionary: Send + Sync {
    fn word_at(&self, index: u16) -> Result<&str>;
    fn index_of(&self, word: &str) -> Result<u16>;
    fn size(&self) -> u16;
    fn bits_per_word(&self) -> u8 {
        (self.size().trailing_zeros() as u8).saturating_sub(1)
    }
}

pub struct Bip39Dictionary {
    words: Vec<String>,
    index_map: std::collections::HashMap<String, u16>,
}

impl Bip39Dictionary {
    pub fn new(word_list: Vec<String>) -> Result<Self> {
        if word_list.len() != 2048 {
            return Err(TransportError::InvalidDictionary(format!("Expected 2048 words, got {}", word_list.len())));
        }
        let mut index_map = std::collections::HashMap::with_capacity(2048);
        for (i, word) in word_list.iter().enumerate() {
            index_map.insert(word.to_lowercase(), i as u16);
        }
        Ok(Self { words: word_list, index_map })
    }

    pub fn english() -> Self {
        let mut words: Vec<String> = ENGLISH_WORDS.iter().map(|&w| w.to_string()).collect();
        let base_len = words.len();
        for i in base_len..2048 { words.push(format!("word{:04}", i)); }
        let mut index_map = std::collections::HashMap::with_capacity(2048);
        for (i, word) in words.iter().enumerate() { index_map.insert(word.clone(), i as u16); }
        Self { words, index_map }
    }

    pub fn to_natural_sentence(&self, encoded: &[u16]) -> String {
        if encoded.is_empty() { return String::new(); }
        let words: Vec<&str> = encoded.iter().map(|&idx| self.words[idx as usize].as_str()).collect();
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

    pub fn from_natural_sentence(&self, sentence: &str) -> Result<Vec<u16>> {
        let cleaned = sentence.to_lowercase().replace(|c: char| c == '.' || c == ',' || c == '!' || c == '?', " ");
        Ok(cleaned.split_whitespace().filter_map(|word| self.index_map.get(word).copied()).collect())
    }
}

impl WordDictionary for Bip39Dictionary {
    fn word_at(&self, index: u16) -> Result<&str> {
        self.words.get(index as usize).map(|s| s.as_str()).ok_or_else(|| TransportError::InvalidIndex(index))
    }
    fn index_of(&self, word: &str) -> Result<u16> {
        self.index_map.get(word).copied().ok_or_else(|| TransportError::UnknownWord(word.to_string()))
    }
    fn size(&self) -> u16 { 2048 }
}

const ENGLISH_WORDS: &[&str] = &[
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","achieve","acid","acoustic","acquire","across","act","action",
    "actor","actual","adapt","add","address","adjust","admit","adult","advance","advice",
    "aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air",
    "airport","aisle","alarm","album","alert","alien","alive","all","alley","allow","almost",
    "alone","alpha","also","alter","always","amateur","amazing","among","amount","amused",
    "anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another",
    "answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve",
    "april","arch","arctic","area","arena","argue","arise","armor","around","arrange",
    "arrest","arrive","arrow","art","artist","ash","ask","asleep","aspect","assault",
    "asset","assist","assume","asthma","athlete","atom","attach","attack","attend","attract",
    "auction","audio","august","aunt","average","avoid","awake","award","aware","away",
    "awesome","awful","axis","baby","back","bacon","badge","bag","bake","balance","balcony",
    "ball","bamboo","banana","band","bank","banner","bar","barely","bargain","barrel",
    "base","basic","basket","battle","beach","bean","bear","beast","beauty","become",
    "beef","before","begin","behave","behind","being","belief","bell","belong","below",
    "belt","bench","benefit","berry","best","better","between","beyond","bicycle","bid",
    "bike","bill","bind","biology","bird","birth","bitter","black","blade","blame",
    "blank","blast","bless","blind","block","blood","bloom","blossom","blouse","blue",
    "blur","board","boat","body","boil","bold","bolt","bomb","bond","bone","bonus",
    "book","boost","boot","border","boring","borrow","boss","bottle","bottom","bounce",
    "boundary","bowl","brain","brake","branch","brand","brass","brave","bread","break",
    "breath","brick","bridge","brief","bright","bring","broad","brother","brown","brush",
    "bubble","bucket","budget","buffalo","build","bulb","bulk","bullet","bundle","burden",
    "burger","burst","bus","bush","business","busy","butter","butterfly","button","buyer",
    "buzz","cabin","cable","cactus","cage","cake","calculate","calendar","call","calm",
    "camel","camera","camp","canal","cancel","cancer","candle","candy","canvas","canyon",
    "capable","capital","captain","capture","car","carbon","card","cargo","carpet","carry",
    "cart","carve","case","cash","casino","castle","casual","cat","catalog","catch",
    "category","cattle","caught","cause","caution","cave","ceiling","celebrate","cell","cement",
    "center","cereal","certain","chain","chair","chalk","challenge","chamber","champion",
    "chance","change","channel","chaos","chapter","charge","charm","chart","chase","chat",
    "cheap","check","cheek","cheer","chef","chest","chicken","chief","child","chimney",
    "choice","choose","chronic","chunk","church","cigar","cinema","circle","citizen","city",
    "civil","claim","clarify","claw","clay","clean","clear","clerk","click","client",
    "cliff","climate","climb","clinic","clip","clock","close","cloth","cloud","club",
    "clue","cluster","coach","coast","coconut","code","coffee","coil","coin","collect",
    "college","color","column","combat","combine","comedy","comfort","comic","command",
    "comment","common","company","compare","compass","compete","complete","complex",
    "concept","concern","concert","confirm","connect","consent","consider","console",
    "contact","contain","content","contest","context","control","convert","cook","cool",
    "copy","coral","corner","correct","cost","cotton","couch","could","council","count",
    "country","couple","courage","course","court","cousin","cover","cow","crack","craft",
    "crash","crawl","crazy","cream","create","credit","crew","cricket","crime","crisp",
    "critic","crop","cross","crowd","crown","crucial","cruel","cruise","crush","crystal",
    "cube","culture","cup","cupboard","cure","curious","current","curtain","curve","cushion",
    "custom","cycle","dad","daily","dairy","dam","damage","dance","danger","daring",
    "dark","dash","data","date","daughter","dawn","day","deal","debate","debris",
    "decade","december","decide","decline","decorate","decrease","deer","defense","define",
    "degree","delay","deliver","delta","demand","denial","density","deny","depart","depend",
    "deposit","depth","deputy","derive","descent","describe","desert","design","desk",
    "despair","destroy","detail","detect","develop","device","devote","diagram","diamond",
    "diary","dictate","diesel","diet","differ","digital","dignity","dilemma","dinner",
    "diploma","direct","dirt","discuss","disease","dish","dismiss","display","distance",
    "diverse","divide","divine","dizzy","doctor","document","dog","doll","dolphin","domain",
    "donate","donkey","door","dose","double","dove","draft","dragon","drain","drama",
    "draw","dream","dress","drift","drill","drink","drive","drop","drought","drown",
    "drum","dry","duck","dumb","during","dust","duty","dwarf","dynamic","eager","eagle",
    "early","earn","earth","ease","east","easy","echo","economy","edge","edit","educate",
    "effect","effort","egg","eight","either","elbow","elder","elect","elegant","element",
    "elephant","elite","else","embrace","emerge","emotion","employ","empty","enact",
    "end","enemy","energy","enforce","engage","engine","enjoy","enough","enroll","ensure",
    "enter","entire","entry","envelope","equal","erase","escape","essay","essence","estate",
    "eternal","ethics","evoke","exact","example","exceed","excel","except","excess",
    "exchange","excite","excuse","execute","exercise","exhaust","exhibit","exile","exist",
    "exit","exotic","expand","expect","expert","explain","explode","explore","expose",
    "express","extend","extra","eye","fabric","face","fact","factor","fade","fail",
    "faint","fair","faith","fake","fall","false","fame","family","famous","fancy",
    "fantasy","far","farm","fashion","fast","fatal","father","fatigue","fault","favor",
    "fear","feast","feature","federal","fee","feed","feel","fellow","fence","festival",
    "fetch","fever","few","fiber","fiction","field","fierce","fight","figure","file",
    "filter","final","finance","find","fine","finger","finish","fire","firm","first",
    "fish","fist","fit","fitness","fix","flag","flame","flash","flavor","flee","fleet",
    "flesh","flight","float","flock","flood","floor","flour","flow","flower","fluid",
    "flush","flute","fly","foam","focus","fog","foil","fold","folk","follow","fond",
    "font","food","fool","foot","force","forest","forget","fork","form","fortune",
    "forum","fossil","foster","found","fox","frame","frequent","fresh","friend","fringe",
    "frog","front","frost","frown","frozen","fruit","fuel","fulfil","full","fun",
    "function","fund","funny","fur","fury","future","gadget","gain","galaxy","gallery",
    "game","gap","garage","garden","garlic","gas","gate","gather","gauge","gaze",
    "gear","gem","gender","general","genius","gentle","genuine","gesture","ghost",
    "giant","gift","giraffe","girl","give","glad","glance","glass","gleam","glide",
    "glimpse","globe","gloom","glory","glove","glow","glue","goal","goat","gold",
    "golf","gone","good","goose","gorge","govern","grace","grade","grain","grand",
    "grant","grape","graph","grasp","grass","gravity","great","green","greet","grid",
    "grief","grill","grin","grind","grip","grocery","ground","group","grow","guard",
    "guess","guest","guide","guild","guilt","guitar","gulf","gun","gust","gym",
    "habit","hair","half","hall","halt","hammer","hand","handle","hang","happen",
    "happy","harbor","hard","harm","harvest","hat","hatch","hate","have","hawk",
    "hazard","head","heal","health","heap","hear","heart","heat","heaven","heavy",
    "hedge","heel","height","help","hen","herb","herd","here","hero","hidden",
    "high","hill","hint","hip","hire","history","hit","hobby","hold","hole",
    "holiday","hollow","holy","home","honest","honey","honor","hook","hope",
    "horizon","horn","horror","horse","host","hotel","hour","house","hover","how",
    "huge","human","humble","humor","hunger","hunt","hurdle","hurry","hurt",
    "husband","hybrid","ice","icon","idea","ideal","identify","idle","ignite",
    "ignore","ill","image","imagine","impact","imply","import","impose","impress",
    "improve","impulse","inch","include","income","increase","index","indicate",
    "indoor","industry","infant","inform","inherit","initial","inject","injury",
    "inmate","inner","input","inquiry","insect","insert","inside","insight","insist",
    "inspire","install","instance","intact","intend","interest","internal","interval",
    "intimate","into","invade","invent","invest","invite","involve","iron","island",
    "isolate","issue","item","ivory","jacket","jade","jail","jam","jar","jaw",
    "jazz","jealous","jeans","jelly","jet","jewel","job","jockey","join","joint",
    "joke","jolly","journal","journey","joy","judge","juice","jump","jungle",
    "junior","jury","just","justice","keen","keep","kernel","kettle","key","kick",
    "kid","kind","king","kiss","kit","kitchen","kite","kitten","knee","knife",
    "knight","knit","knock","knot","know","label","labor","ladder","lady","lake",
    "lamb","lamp","land","lane","language","large","last","late","later","latest",
    "laugh","launch","laundry","law","lawn","layer","lazy","lead","leaf","league",
    "leak","lean","learn","lease","leather","leave","lecture","left","leg","legacy",
    "legal","legend","lemon","lend","length","lens","leopard","lesson","letter",
    "level","lever","liar","liberal","liberty","library","license","life","lift",
    "light","like","likely","lily","limb","limit","line","linen","link","lion",
    "lip","liquid","list","listen","liter","little","live","liver","living","lizard",
    "load","loan","lobby","local","locate","lock","logic","lonely","long","look",
    "loop","loose","lord","lose","loss","lot","loud","love","low","loyal","luck",
    "lucky","luggage","lunch","lung","luxury","lyric","machine","mad","magic",
    "magnet","maid","mail","main","major","make","male","mall","mammal","man",
    "manage","mango","manner","mansion","manual","many","map","marble","march",
    "margin","marine","mark","market","marriage","marry","mask","mass","master",
    "match","mate","matrix","matter","mature","maximum","maybe","mayor","maze",
    "meadow","meal","mean","measure","meat","mechanic","medal","media","median",
    "medical","medium","meet","melt","member","memory","mental","mention","menu",
    "mercy","merge","merit","merry","mesh","message","metal","method","middle",
    "midnight","might","mild","mile","milk","mill","mimic","mind","mine","minimum",
    "minister","mint","minute","miracle","mirror","misery","miss","mistake","mix",
    "mobile","mock","model","moderate","modern","modest","modify","module","moist",
    "moment","money","monitor","monkey","month","mood","moon","moral","morning",
    "mortal","mosquito","mother","motion","motive","motor","mount","mountain",
    "mouse","mouth","move","movie","much","mud","muffin","mule","multiply","muscle",
    "museum","mushroom","music","must","mutual","mystery","myth","nail","name",
    "napkin","narrow","nasty","nation","native","natural","nature","navy","near",
    "neat","neck","need","needle","negative","neglect","nerve","nest","net",
    "network","neutral","never","news","next","nice","niche","niece","night",
    "nine","noble","nod","noise","nominal","none","noodle","noon","normal","north",
    "nose","notable","note","nothing","notice","novel","nuclear","number","nurse",
    "nut","oak","oasis","obey","object","oblige","observe","obtain","obvious",
    "occur","ocean","october","odor","off","offer","office","officer","often",
    "oil","okay","old","olive","olympic","omit","once","onion","online","only",
    "onset","open","opera","operate","opinion","oppose","optic","option","orange",
    "orbit","orchard","order","ordinary","organ","orient","origin","orphan",
    "ostrich","other","outcome","outdoor","outer","outlet","outline","output",
    "outside","oval","oven","over","overt","owe","own","owner","oxygen","oyster",
    "pace","pack","paddle","page","pain","paint","pair","palace","pale","palm",
    "pan","panel","panic","paper","parade","parent","park","parrot","part",
    "particle","partner","party","pass","passion","passive","past","patch",
    "patent","path","patience","patient","patrol","patron","pattern","pause",
    "pave","payment","peace","peach","peak","pearl","pedal","peer","pen","penalty",
    "pencil","people","pepper","perfect","perform","perfume","period","permit",
    "person","pet","phase","phone","photo","phrase","physical","piano","pick",
    "picture","piece","pig","pigeon","pile","pilot","pin","pine","pink","pipe",
    "pistol","pitch","pizza","place","plain","plan","plane","planet","plant",
    "plastic","plate","platform","plaza","plead","pleasant","pledge","plenty",
    "plot","plunge","plural","pocket","poem","poet","poetry","point","poison",
    "polar","pole","police","policy","polite","political","poll","pollen","pond",
    "pony","pool","poor","popular","port","portion","portrait","position",
    "positive","possess","possible","post","potato","potential","pound","pour",
    "powder","power","practice","praise","prayer","preach","precious","predict",
    "prefer","prefix","pregnant","premier","premium","prepare","present","preserve",
    "president","press","pretty","prevent","price","pride","primary","prime",
    "prince","princess","print","prior","prison","private","prize","probe",
    "problem","process","produce","profit","program","progress","project",
    "promise","promote","proof","proper","property","prose","protect","protein",
    "protest","proud","prove","provide","province","pump","punch","punish",
    "pupil","puppy","purchase","pure","purple","purpose","purse","push","put",
    "puzzle","pyramid","quaint","quality","quantum","quarter","queen","query",
    "quest","question","quick","quiet","quilt","quit","quiz","quote","rabbit",
    "race","rack","radar","radio","raft","rage","rail","rain","raise","rally",
    "ranch","random","range","rank","rapid","rare","rat","rate","rather","raven",
    "raw","ray","reach","react","ready","real","reality","realize","realm",
    "reason","rebel","recall","receive","recent","recess","recipe","reckon",
    "record","recover","recruit","reduce","refer","refine","reflect","reform",
    "refuse","regard","regime","region","regret","regular","reject","relate",
    "relax","relay","release","relevant","reliable","relief","relieve","remain",
    "remark","remedy","remind","remote","remove","render","renew","rent","repair",
    "repeat","replace","reply","report","represent","reproduce","request",
    "require","rescue","research","resemble","reserve","reside","resign","resist",
    "resolve","resort","resource","respect","respond","response","rest","restore",
    "result","retain","retire","retreat","return","reveal","revenge","revenue",
    "review","revise","revival","revive","reward","rhythm","rib","ribbon","rice",
    "rich","ride","ridge","rifle","right","rigid","ring","riot","ripe","rise",
    "risk","ritual","rival","river","road","roar","roast","rob","robot","rock",
    "rocket","rod","role","roll","romance","roof","room","root","rope","rose",
    "rotate","rough","round","route","routine","royal","rub","ruby","rug","ruin",
    "rule","ruler","run","runner","rural","rush","rust","sack","sacred","sacrifice",
    "sad","saddle","safe","safety","sage","sail","saint","salad","salary","sale",
    "salmon","salon","salt","salute","same","sample","sand","sandal","sandwich",
    "sane","satellite","satisfy","sauce","sausage","save","savor","say","scale",
    "scan","scare","scarf","scene","scent","schedule","scheme","scholar","school",
    "science","scout","scrape","scratch","scream","screen","script","scroll",
    "sculpture","sea","seal","search","season","seat","second","secret","section",
    "sector","secure","security","see","seed","seek","seem","segment","select",
    "self","sell","send","senior","sense","sensible","sensitive","sentence",
    "separate","sequence","series","serious","serve","service","session","set",
    "settle","seven","severe","sew","shade","shadow","shake","shallow","shame",
    "shape","share","shark","sharp","shave","shed","sheep","sheet","shelf",
    "shell","shelter","shield","shift","shine","ship","shirt","shiver","shock",
    "shoe","shoot","shop","shore","short","shot","shoulder","shout","show",
    "shower","shrimp","shrink","shrug","shut","shy","sick","side","siege",
    "sight","sign","signal","signature","significance","silent","silk","silly",
    "silver","similar","simple","since","sing","singer","single","sink","sir",
    "sister","sit","site","situation","six","size","skate","sketch","skill",
    "skin","skip","skirt","skull","sky","slab","slam","slap","slave","sleep",
    "slice","slide","slight","slim","slip","slope","slow","small","smart",
    "smash","smell","smile","smoke","smooth","snack","snake","snap","snow",
    "soak","soap","soccer","social","sock","socket","soda","soft","soil",
    "solar","soldier","solid","solo","solve","some","son","song","soon","sore",
    "sorrow","sort","soul","sound","soup","source","south","space","spare",
    "spark","sparkle","sparrow","speak","speaker","spear","special","species",
    "specific","spectrum","speech","speed","spell","spend","sphere","spider",
    "spike","spill","spin","spine","spirit","spite","splash","split","spoil",
    "sponge","spoon","sport","spot","spouse","spray","spread","spring","spruce",
    "spy","square","squash","squat","squeak","squeeze","squirrel","stab","stable",
    "stack","stadium","staff","stage","stain","stair","stake","stale","stall",
    "stamp","stand","star","stare","start","starve","state","station","statue",
    "status","stay","steady","steak","steal","steam","steel","steep","steer",
    "stem","step","stereo","stern","stew","stick","stiff","still","sting",
    "stir","stitch","stock","stomach","stone","stool","stop","store","storm",
    "story","stove","straight","strain","strand","strange","stranger","strap",
    "strategy","straw","stray","stream","street","strength","stress","stretch",
    "strict","strike","string","strip","stripe","strive","stroke","strong",
    "struggle","student","studio","study","stuff","stumble","stupid","style",
    "subject","suburb","subway","succeed","success","such","sudden","suffer",
    "sugar","suggest","suit","sulfur","sum","summer","summit","sun","super",
    "supply","support","supreme","sure","surface","surge","surgeon","surgery",
    "surplus","surprise","surrender","survey","survive","suspect","suspend",
    "sustain","swallow","swamp","swan","swarm","swear","sweat","sweep","sweet",
    "swell","swift","swim","swing","switch","sword","symbol","symptom","system",
    "table","tablet","tackle","tactic","tail","talent","talk","tall","tame",
    "tank","tap","tape","target","task","taste","tattoo","taxi","tea","teach",
    "teacher","team","tear","tease","teaspoon","tech","tell","temper","temple",
    "tempo","tempt","tenant","tend","tender","tennis","tense","tent","term",
    "terrace","terrain","terrible","terror","test","text","thank","theater",
    "theme","then","theory","therapy","there","thesis","thick","thief","thigh",
    "thin","thing","think","thirst","this","thorn","thorough","those","thought",
    "thread","threat","three","threshold","thrift","thrill","thrive","throat",
    "throne","through","throw","thrust","thumb","thunder","ticket","tide",
    "tidy","tie","tiger","tight","tile","tilt","timber","time","timid","tin",
    "tiny","tip","tire","tissue","title","toast","tobacco","today","toe",
    "together","toilet","token","tolerate","toll","tomato","tomorrow","tone",
    "tongue","tool","tooth","top","topic","torch","tornado","tortoise","toss",
    "total","touch","tough","tour","tourist","toward","towel","tower","town",
    "toxic","toy","trace","track","trade","traffic","tragic","trail","train",
    "trait","tram","trance","transfer","transform","transition","translate",
    "transmit","transport","trap","trash","travel","tray","treasure","treat",
    "treaty","tree","tremble","trend","trial","tribe","tribunal","tribute",
    "trick","trigger","trim","trip","triple","troop","trophy","trouble",
    "trouser","truck","true","truly","trumpet","trunk","trust","truth","try",
    "tube","tuna","tune","tunnel","turkey","turn","turtle","tutor","twelve",
    "twenty","twice","twin","twist","type","typical","tyrant","ugly","ulcer",
    "ultimate","umbrella","unable","uncle","uncover","under","undo","unfair",
    "unfold","unhappy","uniform","union","unique","unit","unite","unity",
    "universe","university","unknown","unless","unlike","unload","unlock",
    "until","unusual","upgrade","uphold","upon","upper","upset","urban",
    "urge","urgent","usage","use","used","useful","usual","utility","vacant",
    "vacation","vague","vain","valid","valley","value","valve","van","vanish",
    "various","vary","vase","vast","vault","vector","vegetable","vehicle",
    "veil","vein","vendor","venture","verb","verdict","verify","version",
    "vessel","veteran","veto","viable","vibrant","vice","victim","victory",
    "video","view","village","vintage","violin","virtual","virtue","virus",
    "visible","vision","visit","visual","vital","voice","void","volcano",
    "volume","volunteer","vote","vowel","voyage","wage","wagon","waist",
    "wait","wake","walk","wall","wander","want","war","ward","warm","warn",
    "warp","warrior","wash","wasp","waste","watch","water","wave","wax",
    "way","weak","wealth","weapon","wear","weather","weave","wedding","week",
    "weird","welcome","welfare","well","west","wet","whale","what","wheat",
    "wheel","when","where","whether","which","while","whip","whisper","whistle",
    "white","who","whole","why","wicked","wide","widow","width","wife","wild",
    "will","win","wind","window","wine","wing","wink","winner","winter","wipe",
    "wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood",
    "wool","word","work","world","worm","worry","worth","would","wound","wrap",
    "wreck","wrist","write","wrong","yard","yarn","year","yearn","yellow",
    "yes","yesterday","yield","young","youth","zebra","zero","zone","zoo","zoom",
];
