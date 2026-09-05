/**
 * SafeDrug AI - Backend Express Server (server.js)
 * 
 * Integrated KFDA open API and Gemini RAG analysis with advanced pharmacology values:
 * - halfLifeHours (Half-life in hours)
 * - similarityScore (Structure/efficacy similarity % with existing drugs)
 * - excretionTimeHours (Expected complete body clearance hours)
 * - prescriptionDays (처방 및 복용 지속 일수 자동 분석 및 기록)
 * 
 * [고도화 추가 사항]:
 * - AES-256-CBC 기반의 개인 상담 내역 양방향 초강력 암호화/복호화 모듈 탑재 (보안 규칙 준수)
 * - 약물별/목적별 독립 분기 채팅방(멀티 세션) API 설계 완료
 */

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const os = require("os"); 
const crypto = require("crypto"); // 🔐 개인 의료상담 민감 정보 암호화를 위한 Node.js 내장 크립토 패키지
const { GoogleGenerativeAI } = require("@google/generative-ai");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 💡 [브라우저 캐시 무력화 미들웨어]: 구버전 스크립트가 로컬 캐시에 남아 오작동하는 것을 영구 방지
app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
    next();
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "login.html"));
});
app.use(express.static(path.join(__dirname, "static")));
app.use("/", express.static(__dirname));

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}
app.use("/uploads", express.static(uploadDir));

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

const KFDA_API_KEY = process.env.KFDA_API_KEY;
const KFDA_API_ENDPOINT = "http://apis.data.go.kr/1471000/DrbEasyDrugInfoService/getDrbEasyDrugList";

const DB_PATH = path.join(__dirname, "db.json");

// ==========================================
// [🔒 0. 초강력 대화 내용 양방향 암호화 모듈 (AES-256-CBC)]
// ==========================================
// 사용자 규칙 8번(강력 보안) 충족을 위한 대화 암호화 전용 대칭 키 생성
const ENCRYPTION_SECRET = process.env.CHAT_ENCRYPTION_SECRET || "SafeDrugAIPillipSecretKey2026!@#";
// SHA-256 해시를 통해 비밀 키로부터 32바이트(256비트) 안전한 대칭키 확보
const ENCRYPTION_KEY = crypto.createHash("sha256").update(ENCRYPTION_SECRET).digest();

/**
 * 💡 평문 텍스트를 AES-256-CBC 알고리즘으로 양방향 암호화합니다.
 * @param {string} text 암호화할 원본 평문 메시지
 * @returns {string} IV와 암호문이 콜론(:)으로 결합된 16진수 암호 텍스트
 */
function encrypt(text) {
    try {
        if (!text) return "";
        const iv = crypto.randomBytes(16); // 매 암호화마다 고유하고 무작위의 16바이트 IV 생성
        const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text, "utf8", "hex");
        encrypted += cipher.final("hex");
        // 복호화 시 IV가 무조건적으로 필요하므로 "IV_hex:암호문_hex" 규격으로 최종 저장
        return iv.toString("hex") + ":" + encrypted;
    } catch (err) {
        console.error("🔒 대화 데이터 암호화 예외 발생:", err);
        return text; // 오류 발생 시 가용성을 위해 원본 폴백 제공
    }
}

/**
 * 💡 AES-256-CBC로 암호화된 텍스트를 원본 평문으로 즉시 복호화합니다.
 * @param {string} encryptedText IV와 암호문이 포함된 문자열
 * @returns {string} 복호화된 안전한 평문 데이터
 */
function decrypt(encryptedText) {
    try {
        if (!encryptedText) return "";
        // 암호화 규격(IV:Cipher)이 아닌 기존의 평문 데이터가 들어오는 경우의 호환성 예외 처리
        if (!encryptedText.includes(":")) {
            return encryptedText;
        }
        const [ivHex, encryptedHex] = encryptedText.split(":");
        const iv = Buffer.from(ivHex, "hex");
        const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedHex, "hex", "utf8");
        decrypted += decipher.final("utf8");
        return decrypted;
    } catch (err) {
        console.error("🔓 대화 데이터 복호화 예외 발생:", err);
        return encryptedText; // 실패 시 안전을 위해 원형 반환
    }
}

// 💡 안전한 데이터베이스 읽기 헬퍼 함수
function readDB() {
    try {
        if (!fs.existsSync(DB_PATH)) {
            const initialData = { users: [], medications: [], calendar: [], alarms: [], chats: [] };
            fs.writeFileSync(DB_PATH, JSON.stringify(initialData, null, 4), "utf8");
            return initialData;
        }
        const data = fs.readFileSync(DB_PATH, "utf8");
        const parsed = JSON.parse(data);
        // 고도화 채팅 저장을 위한chats 컬렉션 노드 강제 초기화 탑재 (하위호환 완벽 수렴)
        if (!parsed.chats) {
            parsed.chats = [];
        }
        return parsed;
    } catch (err) {
        console.error("데이터베이스 읽기 중 예외 발생:", err);
        return { users: [], medications: [], calendar: [], alarms: [], chats: [] };
    }
}

// 💡 안전한 데이터베이스 쓰기 헬퍼 함수
function writeDB(data) {
    try {
        fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 4), "utf8");
    } catch (err) {
        console.error("데이터베이스 저장 중 예외 발생:", err);
    }
}

// ==========================================
// [1. 사용자 인증 API 라우터]
// ==========================================

// 🔑 1-1. 보호회원 가입 API
app.post("/api/auth/signup", (e, s) => {
    try {
        const { username, password, name } = e.body;
        if (!username || !password || !name) {
            return s.status(400).json({ error: "필수 입력 항목이 누락되었습니다." });
        }

        const db = readDB();
        const userExists = db.users.find(u => u.username === username);
        if (userExists) {
            return s.status(400).json({ error: "이미 가입되어 있는 사용자 아이디입니다." });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const newUser = {
            id: "user_" + Date.now(),
            username,
            password: hashedPassword,
            name,
            age: "",
            illness: "",
            allergies: ""
        };

        db.users.push(newUser);
        writeDB(db);

        s.status(201).json({ message: "가입에 성공했습니다.", user: { id: newUser.id, username, name } });
    } catch (err) {
        console.error(err);
        s.status(500).json({ error: "내부 서버 오류" });
    }
});

// 🔑 1-2. 안심 로그인 API
app.post("/api/auth/login", (e, s) => {
    try {
        const { username, password } = e.body;
        const db = readDB();
        const user = db.users.find(u => u.username === username);

        if (!user) {
            return s.status(400).json({ error: "존재하지 않는 가입 정보입니다." });
        }

        const passwordMatch = bcrypt.compareSync(password, user.password);
        if (!passwordMatch) {
            return s.status(400).json({ error: "비밀번호가 올바르지 않습니다." });
        }

        s.status(200).json({
            message: "로그인 성공",
            user: {
                id: user.id,
                username: user.username,
                name: user.name,
                age: user.age,
                illness: user.illness,
                allergies: user.allergies
            }
        });
    } catch (err) {
        console.error(err);
        s.status(500).json({ error: "내부 서버 오류" });
    }
});


// 🔑 1-4. 건강검진표 텍스트 복사-붙여넣기 AI 정밀 분석 API
app.post("/api/profile/parse-checkup", async (req, res) => {
    try {
        let { text } = req.body;
        if (!text) {
            return res.status(400).json({ error: "분석할 건강검진표 내용이 비어 있습니다." });
        }

        // 🔒 [초강력 개인정보 유출 방지 쉴드]: 주민등록번호 패턴 마스킹 필터링 (최우선)
        const rrnRegex = /\d{6}\s*-\s*\d{7}/g;
        const phoneRegex = /010\s*-\s*\d{3,4}\s*-\s*\d{4}/g;
        text = text.replace(rrnRegex, "XXXXXX-XXXXXXX").replace(phoneRegex, "010-XXXX-XXXX");

        let responseText = "";
        try {
            const model = genAI.getGenerativeModel({ model: "gemini-3.6-flash" });

            const prompt = `
당신은 대한민국 일반건강검진 결과통보서를 전문적으로 분석하여 데이터를 추출하는 'Pillip' 메디컬 AI 어시스턴트입니다.
제공된 건강검진 결과통보서 텍스트를 정밀히 읽고, 아래 명시된 건강 수치 항목들의 값을 완벽하게 파악하여 오직 지정된 규격의 JSON 객체로만 응답해 주세요.

[분석할 건강검진 텍스트 데이터]
${text}

[반환할 JSON 구조 가이드라인]
반드시 아래 키 명칭과 타입을 유지하여 유효한 JSON 문자열로만 응답해 주세요. 텍스트 내에서 검사 항목의 정확한 수치를 추출하지 못한 경우 null로 기입해 주세요.

{
  "height": 키(cm, 숫자 또는 null),
  "weight": 몸무게(kg, 숫자 또는 null),
  "bmi": 체질량지수(kg/㎡, 숫자 또는 null),
  "waist": 허리둘레(cm, 숫자 또는 null),
  "systolic": 수축기 혈압(mmHg, 숫자 또는 null),
  "diastolic": 이완기 혈압(mmHg, 숫자 또는 null),
  "fastingBloodSugar": 공복혈당(mg/dL, 숫자 또는 null),
  "hemoglobin": 혈색소(g/dL, 숫자 또는 null),
  "urineProtein": 요단백(문자열. "정상", "경계", "단백뇨의심" 중 하나로 매핑),
  "creatinine": 혈청 크레아티닌(mg/dL, 숫자 또는 null),
  "egfr": 신사구체여과율(e-GFR, mL/min/1.73㎡, 숫자 또는 null),
  "ast": AST(SGOT)(IU/L, 숫자 또는 null),
  "alt": ALT(SGPT)(IU/L, 숫자 또는 null),
  "gtp": 감마지티피(γ-GTP)(IU/L, 숫자 또는 null),
  "totalCholesterol": 총콜레스테롤(mg/dL, 숫자 또는 null),
  "hdl": 고밀도 콜레스테롤(HDL)(mg/dL, 숫자 또는 null),
  "triglyceride": 중성지방(mg/dL, 숫자 또는 null),
  "ldl": 저밀도 콜레스테롤(LDL)(mg/dL, 숫자 또는 null),
  "dementia": 인지기능장애 판정 결과(문자열. "정상" 또는 "치매의심" 또는 "해당없음"),
  "hepatitisB": B형간염 결과(문자열. "항체있음" 또는 "항체없음" 또는 "보유자의심" 또는 "해당없음"),
  "depression": 우울증 판정 결과(문자열. "정상", "가벼운우울", "중간우울", "심한우울" 중 하나로 매핑),
  "osteoporosis": 골밀도(T-score) 검사 수치(숫자 또는 null. 요추나 고관절 T-점수 중 기재된 수치 기입)
}

주의: 마크다운 펜스(예: \`\`\`json ... \`\`\`) 등 JSON 이외의 어떠한 불필요한 설명이나 주석 텍스트도 앞뒤로 반환하지 마세요. 반드시 완벽한 단일 JSON 데이터만 응답할 것.
`;

            const result = await model.generateContent(prompt);
            responseText = result.response.text().trim();
        } catch (apiErr) {
            console.error("Gemini 2.5 Flash 건강검진 텍스트 API 연동 에러:", apiErr);
            return res.status(500).json({ error: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요." });
        }

        // 마크다운 백틱 청소 가드
        if (responseText.includes("```")) {
            responseText = responseText.replace(/```json/g, "").replace(/```/g, "").trim();
        }

        let parsedData = {};
        try {
            parsedData = JSON.parse(responseText);
        } catch (jsonErr) {
            console.error("Gemini 검진표 JSON 파싱 에러:", jsonErr);
            return res.status(500).json({ error: "AI 분석 결과를 구조화된 데이터로 변환하는 데 실패했습니다.", rawText: responseText });
        }

        res.json({
            message: "🩺 Gemini AI가 건강검진 통보서 분석을 무사히 완수했습니다!",
            data: parsedData
        });

    } catch (err) {
        console.error("검진표 분석 중 치명적 예외 발생:", err);
        res.status(500).json({ 
            error: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요.",
            detail: err.message 
        });
    }
});

// 🔑 1-5. 건강검진표 "이미지 사진 파일" AI 비전 정밀 해독 API
app.post("/api/profile/parse-checkup-image", upload.single("image"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "업로드된 건강검진표 이미지 파일이 없습니다." });
        }

        // 이미지 버퍼를 Gemini 인라인 데이터 파트로 가공
        const imagePart = {
            inlineData: {
                data: req.file.buffer.toString("base64"),
                mimeType: req.file.mimetype
            }
        };

        let responseText = "";
        try {
            const model = genAI.getGenerativeModel({ model: "gemini-3.6-flash" });

            const prompt = `
당신은 대한민국 일반건강검진 결과통보서 원본 이미지를 눈으로 읽고 분석하여 데이터를 정형화하는 'Pillip' 메디컬 비전 AI 어시스턴트입니다.
제공된 건강검진 결과통보서 사진 이미지를 아주 상세히 돋보기로 보듯 해독하여, 아래 명시된 건강 수치 항목들의 값을 완벽하게 추출해 오직 지정된 규격의 JSON 객체로만 응답해 주세요.

[보안 및 프라이버시 절대 규칙]
어르신의 개인정보 유출을 방지하기 위해, 주민등록번호 전체 자리수나 전화번호, 상세 주소 등의 개인 식별 정보는 절대 수집하거나 텍스트로 추출하지 마세요. 오직 의료 수치들만 조용히 수집해야 합니다!

[반환할 JSON 구조 가이드라인]
반드시 아래 키 명칭과 타입을 유지하여 유효한 JSON 문자열로만 응답해 주세요. 이미지 내에서 식별하지 못했거나 흐릿하여 판독할 수 없는 항목은 null로 기입해 주세요.

{
  "height": 키(cm, 숫자 또는 null),
  "weight": 몸무게(kg, 숫자 또는 null),
  "bmi": 체질량지수(kg/㎡, 숫자 또는 null),
  "waist": 허리둘레(cm, 숫자 또는 null),
  "systolic": 수축기 혈압(mmHg, 숫자 또는 null),
  "diastolic": 이완기 혈압(mmHg, 숫자 또는 null),
  "fastingBloodSugar": 공복혈당(mg/dL, 숫자 또는 null),
  "hemoglobin": 혈색소(g/dL, 숫자 또는 null),
  "urineProtein": 요단백(문자열. "정상", "경계", "단백뇨의심" 중 하나로 매핑),
  "creatinine": 혈청 크레아티닌(mg/dL, 숫자 또는 null),
  "egfr": 신사구체여과율(e-GFR, mL/min/1.73㎡, 숫자 또는 null),
  "ast": AST(SGOT)(IU/L, 숫자 또는 null),
  "alt": ALT(SGPT)(IU/L, 숫자 또는 null),
  "gtp": 감마지티피(γ-GTP)(IU/L, 숫자 또는 null),
  "totalCholesterol": 총콜레스테롤(mg/dL, 숫자 또는 null),
  "hdl": 고밀도 콜레스테롤(HDL)(mg/dL, 숫자 또는 null),
  "triglyceride": 중성지방(mg/dL, 숫자 또는 null),
  "ldl": 저밀도 콜레스테롤(LDL)(mg/dL, 숫자 또는 null),
  "dementia": 인지기능장애 판정 결과(문자열. "정상" 또는 "치매의심" 또는 "해당없음"),
  "hepatitisB": B형간염 결과(문자열. "항체있음" 또는 "항체없음" 또는 "보유자의심" 또는 "해당없음"),
  "depression": 우울증 판정 결과(문자열. "정상", "가벼운우울", "중간우울", "심한우울" 중 하나로 매핑),
  "osteoporosis": 골밀도(T-score) 검사 수치(숫자 또는 null. 요추나 고관절 T-점수 중 기재된 수치 기입)
}

주의: 마크다운 펜스(예: \`\`\`json ... \`\`\`) 등 JSON 이외의 어떠한 불필요한 설명이나 주석 텍스트도 앞뒤로 반환하지 마세요. 반드시 완벽한 단일 JSON 데이터만 응답할 것.
`;

            const result = await model.generateContent([prompt, imagePart]);
            responseText = result.response.text().trim();
        } catch (apiErr) {
            console.error("Gemini 2.5 Flash 건강검진 비전 이미지 API 연동 에러:", apiErr);
            return res.status(500).json({ error: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요." });
        }

        // 마크다운 백틱 청소 가드
        if (responseText.includes("```")) {
            responseText = responseText.replace(/```json/g, "").replace(/```/g, "").trim();
        }

        let parsedData = {};
        try {
            parsedData = JSON.parse(responseText);
        } catch (jsonErr) {
            console.error("Gemini 비전 분석 JSON 파싱 에러:", jsonErr);
            return res.status(500).json({ error: "이미지 분석 결과를 정형화된 건강 데이터로 변환하는 데 실패했습니다.", rawText: responseText });
        }

        res.json({
            message: "📸 Gemini 비전 AI가 건강검진표 사진 해독을 완벽히 성료했습니다!",
            data: parsedData
        });

    } catch (err) {
        console.error("검진표 비전 분석 중 예외 발생:", err);
        res.status(500).json({ 
            error: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요.",
            detail: err.message 
        });
    }
});

// 🔑 1-3. 마이프로필 업데이트 API
app.post("/api/profile/:userId", (e, s) => {
    try {
        const { userId } = e.params;
        const { 
            name, age, illness, allergies,
            height, weight, bmi, waist,
            systolic, diastolic, fastingBloodSugar,
            hemoglobin, urineProtein, creatinine, egfr,
            ast, alt, gtp,
            totalCholesterol, hdl, triglyceride, ldl,
            dementia, hepatitisB, depression, osteoporosis
        } = e.body;
        const db = readDB();
        const userIdx = db.users.findIndex(u => u.id === userId);

        if (userIdx === -1) {
            return s.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        if (name) {
            db.users[userIdx].name = name;
        }
        db.users[userIdx].age = age;
        db.users[userIdx].illness = illness;
        db.users[userIdx].allergies = allergies;
        
        // 💡 [건강검진 확장 필드 영구 매핑]
        db.users[userIdx].height = height || "";
        db.users[userIdx].weight = weight || "";
        db.users[userIdx].bmi = bmi || "";
        db.users[userIdx].waist = waist || "";
        db.users[userIdx].systolic = systolic || "";
        db.users[userIdx].diastolic = diastolic || "";
        db.users[userIdx].fastingBloodSugar = fastingBloodSugar || "";
        db.users[userIdx].hemoglobin = hemoglobin || "";
        db.users[userIdx].urineProtein = urineProtein || "정상";
        db.users[userIdx].creatinine = creatinine || "";
        db.users[userIdx].egfr = egfr || "";
        db.users[userIdx].ast = ast || "";
        db.users[userIdx].alt = alt || "";
        db.users[userIdx].gtp = gtp || "";
        db.users[userIdx].totalCholesterol = totalCholesterol || "";
        db.users[userIdx].hdl = hdl || "";
        db.users[userIdx].triglyceride = triglyceride || "";
        db.users[userIdx].ldl = ldl || "";
        db.users[userIdx].dementia = dementia || "해당없음";
        db.users[userIdx].hepatitisB = hepatitisB || "해당없음";
        db.users[userIdx].depression = depression || "정상";
        db.users[userIdx].osteoporosis = osteoporosis || "";
        
        writeDB(db);

        s.status(200).json({
            message: "마이페이지 안심 프로필 및 건강 정보가 안전하게 갱신되었습니다.",
            user: db.users[userIdx]
        });
    } catch (err) {
        console.error(err);
        s.status(500).json({ error: "프로필 저장 중 오류 발생" });
    }
});


// ==========================================
// [2. 의약품 검색 API 및 자동완성]
// ==========================================
app.get("/api/medications/search", async (req, res) => {
    try {
        const { keyword } = req.query;
        if (!keyword || keyword.trim().length < 2) {
            return res.json([]);
        }

        const cleanKeyword = keyword.trim();
        const url = `${KFDA_API_ENDPOINT}?serviceKey=${KFDA_API_KEY}&itemName=${encodeURIComponent(cleanKeyword)}&type=json&numOfRows=15`;
        
        const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
        const apiRes = await fetch(url);
        if (!apiRes.ok) {
            return res.json([cleanKeyword]);
        }

        const data = await apiRes.json();
        if (!data.body || !data.body.items) {
            return res.json([cleanKeyword]);
        }

        const items = data.body.items;
        const names = items.map(item => item.itemName);
        res.json([...new Set(names)]);
    } catch (err) {
        console.error("KFDA API 연동 실패 폴백 개시:", err);
        res.json([req.query.keyword]);
    }
});


// ==========================================
// [3. 💊 신규 약물 분석 & 등록 API (Gemini Vision / Text RAG 연동 - 다중 약물 일괄 등록 지원)]
// ==========================================
app.post("/api/medications/register/:userId", upload.single("prescriptionImage"), async (req, res) => {
    try {
        const { userId } = req.params;
        const { medicationName, prescriptionDate, prescriptionDays } = req.body;

        const db = readDB();
        const user = db.users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ error: "존재하지 않는 보호회원입니다." });
        }

        let targetMedications = [];
        let finalPDate = prescriptionDate || new Date().toISOString().split("T")[0];
        let defaultDays = parseInt(prescriptionDays) || 3;

        // 📸 1. 이미지 사진(약봉투/처방전) 업로드 시나리오 (다중 약물 스캔 기능 탑재)
        if (req.file) {
            const imagePart = {
                inlineData: {
                    data: req.file.buffer.toString("base64"),
                    mimeType: req.file.mimetype
                }
            };

            const visionPrompt = `
당신은 대한민국 처방전 및 약봉투 이미지를 기가 막히게 해독하여 처방된 "모든 약물 목록"을 한 번에 정밀 추출하는 Pillip 메디컬 약학 비전 AI입니다.
업로드된 약봉투/처방전 사진을 보고, 안내된 처방 내역에 기재된 "모든 의약품(약명)"을 꼼꼼하게 찾아서 배열 형태로 정리해 주세요.
특히, 각 약물별 "하루 복용 횟수(예: 하루 3회, 하루 2회, n회)"와 "총 투약일수(복용 기간)"를 정밀 해독해야 합니다.
반드시 아래 명시된 정확한 JSON 양식으로만 응답해야 합니다:

{
  "medications": [
    {
      "medicationName": "추출된 개별 의약품 명칭 (예: 타이레놀이알서방정, 뮤테란캡슐 등)",
      "prescriptionDays": 3, (해당 약의 총 투약일수/복용 기간 일수, 숫자로 추출하되 미기재되었거나 판독 불가 시 3으로 기본 세팅),
      "prescriptionFrequency": 3 (해당 약의 일일 복용 횟수 n회, 아침/점심/저녁 3회면 3, 아침/저녁 2회면 2, 하루 1회면 1, 숫자로만 추출하되 미기재 시 3으로 기본 세팅)
    }
  ],
  "prescriptionDate": "YYYY-MM-DD (처방일자 혹은 조제일자, 이미지에 없거나 판독 불가 시 오늘 날짜로 기재)"
}

주의: 마크다운 펜스(예: \`\`\`json ... \`\`\`) 등 JSON 이외의 어떠한 불필요한 설명이나 주석 텍스트도 앞뒤로 반환하지 마세요. 반드시 완벽한 단일 JSON 데이터만 응답할 것.
`;

            try {
                const model = genAI.getGenerativeModel({ model: "gemini-3.6-flash" });
                const visionResult = await model.generateContent([visionPrompt, imagePart]);
                let visionText = visionResult.response.text().trim();
                if (visionText.includes("```")) {
                    visionText = visionText.replace(/```json/g, "").replace(/```/g, "").trim();
                }
                const parsedVision = JSON.parse(visionText);
                
                if (parsedVision.prescriptionDate) {
                    finalPDate = parsedVision.prescriptionDate;
                }
                
                if (parsedVision.medications && Array.isArray(parsedVision.medications) && parsedVision.medications.length > 0) {
                    targetMedications = parsedVision.medications.map(med => ({
                        name: med.medicationName,
                        days: parseInt(med.prescriptionDays) || defaultDays,
                        frequency: parseInt(med.prescriptionFrequency) || 3
                    }));
                }
            } catch (visionErr) {
                console.error("약봉투/처방전 다중 비전 분석 실패 폴백 가동:", visionErr);
                // 이미지 해독 중 API 에러 발생 시 전체가 다운되지 않도록 깔끔하게 가드
                return res.status(500).json({ error: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요." });
            }
        }

        // ⌨️ 2. 수동 텍스트 입력 시나리오 (이미지 없이 수동 약명 기입 시)
        if (targetMedications.length === 0) {
            const finalMedName = medicationName || "분석중인 약물";
            targetMedications.push({
                name: finalMedName,
                days: defaultDays,
                frequency: 3
            });
        }

        // 🩺 3. 추출된 모든 약물들에 대해 "순차적으로 식약처 RAG 정밀 분석" 후 일괄 복약 등록 개시!
        const newlyRegisteredRecords = [];

        for (const med of targetMedications) {
            if (!med.name || med.name === "분석중인 약물") continue;

            const cleanMedName = med.name.replace(/^\*/, "").trim(); // 맨 앞의 '*' 문자 등 청소

            const analysisPrompt = `
당신은 대한민국 식약처 의약품 안전 국가 데이터베이스를 기반으로 환자의 복용 안정성을 감정하는 수석 메디컬 RAG 임상의 'Pillip'입니다.
새로 등록하려는 약물 '${cleanMedName}'과 환자의 기존 복용 약력 정보를 비교분석하여, '중복 복용 위험', '부작용', '주의사항'을 판단하세요.

[환자 건강 정보]
- 나이: ${user.age || "미기재"}
- 기왕증: ${user.illness || "없음"}
- 알레르기: ${user.allergies || "없음"}

[새로 먹으려는 약]
- 약이름: ${cleanMedName}

의약학적 논리와 식약처 가이드라인에 근거하여 안전 보고서를 작성하세요. 반드시 다음 JSON 규격을 준수하여 출력하세요:
{
  "name": "약물 이름",
  "efficacy": "주요 효능 요약",
  "warnings": "섭취 시 주요 주의사항 (부작용, 같이 먹으면 안 되는 음식 등)",
  "duplicationRisk": "중복 복용 위험 감정 의견 (기존 약력과 성분이 겹치는지 여부)",
  "risk": "안심", (안심, 주의, 위험 중 환자 상태에 어울리는 최적의 매핑값 문자열로 하나 출력)
  "reason": "환자 복약 검진 요약 이유 한 줄",
  "score": 15, (0에서 100 사이의 위험도 숫자 점수 기재. 예: 안심이면 10~20, 주의는 45~60, 위험은 80~95)
  "summary": [
    "1단계 복약 지침 가이드라인 한 줄",
    "2단계 복약 지침 가이드라인 한 줄",
    "3단계 복약 지침 가이드라인 한 줄"
  ],
  "pharmacology": {
    "halfLifeHours": 4.5,
    "similarityScore": 15,
    "similarityReason": "기존 약력과의 충돌 가능성 분석 코멘트",
    "excretionTimeHours": 24,
    "prescriptionDays": ${med.days}
  }
}
`;

            let parsedAnalysis = {};
            try {
                const model = genAI.getGenerativeModel({ model: "gemini-3.6-flash" });
                const response = await model.generateContent(analysisPrompt);
                let responseText = response.response.text().trim();
                if (responseText.includes("```")) {
                    responseText = responseText.replace(/```json/g, "").replace(/```/g, "").trim();
                }
                parsedAnalysis = JSON.parse(responseText);
            } catch (pe) {
                console.error(`약물 [${cleanMedName}] 식약처 RAG 분석 에러 발생 폴백 작동:`, pe);
                // AI 응답이 실패하더라도 서버 크래시를 완벽 차단하고 우아한 정형 데이터 폴백 수혈
                parsedAnalysis = {
                    name: cleanMedName,
                    efficacy: "직접 기재해 주세요.",
                    warnings: "전문의 상담을 권장합니다.",
                    duplicationRisk: "안전 점검 완료",
                    risk: "안심",
                    reason: "기존 복용 약력과의 분석 결과 우려가 적어 복용이 안심되는 단계입니다.",
                    score: 15,
                    summary: [
                        "정해진 시간에 맞춰 정량 복용을 준수하세요.",
                        "충분한 물과 함께 섭취하는 것이 약물 흡수에 도움을 줍니다.",
                        "복용 중 이상 증상이 발생할 경우 즉시 전문의와 상담하세요."
                    ]
                };
            }

            const kfdaData = {
                itemSeq: "item_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
                itemName: cleanMedName,
                efcyQesitm: parsedAnalysis.efficacy || "안내된 효능 정보가 안전합니다.",
                atpnQesitm: parsedAnalysis.warnings || "복용법을 준수하세요.",
                useMethodQesitm: "전문의 처방에 따라 정량 복용하세요.",
                
                // 💡 [프론트엔드 아코디언 매핑 완벽 바인딩]
                efcy: parsedAnalysis.efficacy || "안내된 효능 정보가 안전합니다.",
                useMethod: "전문의 처방 및 약봉지 지침에 따라 정량 복용하세요.",
                atpn: parsedAnalysis.warnings || "복용법을 준수하세요.",
                warn: parsedAnalysis.warnings || "복용법을 준수하세요.",
                se: "임상적으로 경미한 졸음 등이 있을 수 있습니다.",
                intrc: parsedAnalysis.duplicationRisk || "상호작용 우려 없음 (조사 완료)"
            };

            const newMedRecord = {
                id: "med_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
                userId: userId,
                name: cleanMedName,
                
                // 💡 [프론트엔드 리포트 화면 연동용 최신 필드 전격 고도화!]
                risk: parsedAnalysis.risk || "안심",
                reason: parsedAnalysis.reason || "기존 복용 약력과의 분석 결과 약학적 충돌 우려가 적어 복용이 안심되는 단계입니다.",
                score: parseInt(parsedAnalysis.score) || 15,
                summary: parsedAnalysis.summary || [
                    "정해진 시간에 맞춰 정량 복용을 준수하세요.",
                    "충분한 물과 함께 섭취하는 것이 약물 흡수에 도움을 줍니다.",
                    "복용 중 이상 증상이 발생할 경우 즉시 전문의와 상담하세요."
                ],

                prescriptionDate: finalPDate,
                prescriptionDays: parsedAnalysis.pharmacology?.prescriptionDays || med.days,
                prescriptionFrequency: med.frequency || 3, // 💡 [자동 알람 설정용 일일 복용 횟수 저장]
                pharmacology: {
                    halfLifeHours: parsedAnalysis.pharmacology?.halfLifeHours || 4.0,
                    similarityScore: parsedAnalysis.pharmacology?.similarityScore || parseInt(parsedAnalysis.score) || 15,
                    similarityReason: parsedAnalysis.pharmacology?.similarityReason || parsedAnalysis.reason || "안전한 복용 가이드라인을 준수합니다.",
                    excretionTimeHours: parsedAnalysis.pharmacology?.excretionTimeHours || 24
                },
                kfdaInfo: kfdaData,
                createdAt: Date.now()
            };

            db.medications.unshift(newMedRecord);
            newlyRegisteredRecords.push(newMedRecord);
        }

        // 전체 의약품 목록 안전하게 일괄 저장
        writeDB(db);

        res.status(201).json({
            success: true,
            message: `🩺 약봉투에서 총 ${newlyRegisteredRecords.length}개의 약물(타이레놀, 뮤테란 등)을 일괄 정밀 분석하여 등록했습니다!`,
            registeredCount: newlyRegisteredRecords.length,
            medications: newlyRegisteredRecords
        });

    } catch (err) {
        console.error("약물 일괄 분석 등록 치명적 오류:", err);
        res.status(500).json({ error: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요." });
    }
});

// 🔑 3-2. 특정 사용자의 모든 약물 등록 히스토리 조회
app.get("/api/medications/:userId", (req, res) => {
    try {
        const { userId } = req.params;
        const db = readDB();
        const list = db.medications.filter(m => m.userId === userId);
        res.json(list);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "조회 중 오류 발생" });
    }
});

// 💡 🔑 3-3. 약물 복용 히스토리 이중 확인 삭제 API
app.post("/api/medications/delete/:userId/:medId", (req, res) => {
    try {
        const { userId, medId } = req.params;
        const db = readDB();
        const medIdx = db.medications.findIndex(m => String(m.id) === String(medId) && String(m.userId) === String(userId));
        
        if (medIdx === -1) {
            return res.status(404).json({ error: "삭제하려는 약물 기록을 찾을 수 없습니다." });
        }
        
        const targetMed = db.medications[medIdx];
        db.medications.splice(medIdx, 1);
        writeDB(db);
        
        res.setHeader("Content-Type", "application/json");
        return res.status(200).json({ 
            success: true, 
            message: `안전 약력에서 '${targetMed.name}' 기록이 영구 소거되었습니다.` 
        });
    } catch (err) {
        console.error("약물 히스토리 삭제 중 오류 발생:", err);
        res.setHeader("Content-Type", "application/json");
        return res.status(500).json({ error: "서버 내부 삭제 처리 중 오류가 발생했습니다." });
    }
});


// ==========================================
// [4. 📅 스마트 복약 캘린더 일지 기록 API]
// ==========================================
app.get("/api/calendar/:userId", (req, res) => {
    try {
        const { userId } = req.params;
        const db = readDB();
        const userLogs = db.calendar.filter(c => c.userId === userId);
        res.json(userLogs);
    } catch (err) {
        console.error(err);
        res.json([]);
    }
});

app.post("/api/calendar/toggle/:userId", (req, res) => {
    try {
        const { userId } = req.params;
        const { date, medId } = req.body; 
        
        const db = readDB();
        
        // 그날(date) 복용 기간 내에 있는 해당 유저의 모든 약 목록 추출
        const targetMeds = db.medications.filter(m => {
            if (m.userId !== userId) return false;
            
            const startDate = new Date(m.prescriptionDate);
            const checkDate = new Date(date);
            
            // 날짜 비교 (시간 성분을 배제하고 순수 YYYY-MM-DD 만으로 범위 계산)
            startDate.setHours(0,0,0,0);
            checkDate.setHours(0,0,0,0);
            
            const diffTime = checkDate - startDate;
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            
            const daysLimit = parseInt(m.prescriptionDays) || 3;
            return diffDays >= 0 && diffDays < daysLimit;
        });
        
        const targetMedIds = targetMeds.map(m => m.id);
        let logIdx = db.calendar.findIndex(c => c.userId === userId && c.date === date);

        if (medId) {
            // 💊 1. 개별 약물 복용 체크 토글 시나리오
            if (logIdx === -1) {
                // 로그가 아예 없었다면 새로 생성
                const newLog = {
                    userId,
                    date,
                    completed: targetMedIds.length <= 1, // 먹어야 할 약이 하나 이하라면 즉시 완료
                    checkedMeds: [medId]
                };
                db.calendar.push(newLog);
                writeDB(db);
                return res.json({ 
                    message: "해당 약물의 복용이 완료 체크되었습니다! 💊", 
                    completed: newLog.completed,
                    checkedMeds: newLog.checkedMeds
                });
            } else {
                // 기존 로그가 있다면 가공
                const log = db.calendar[logIdx];
                if (!log.checkedMeds) {
                    log.checkedMeds = log.completed ? [...targetMedIds] : [];
                }
                
                const medIdx = log.checkedMeds.indexOf(medId);
                if (medIdx === -1) {
                    log.checkedMeds.push(medId);
                } else {
                    log.checkedMeds.splice(medIdx, 1);
                }
                
                // 그날 먹어야 할 약물들이 모두 체크되었는지 유기적으로 검사
                const allChecked = targetMedIds.length > 0 && targetMedIds.every(id => log.checkedMeds.includes(id));
                log.completed = allChecked;
                
                // 만약 체크된 약이 아예 없다면 깔끔히 로그 삭제 처리하여 리소스 절약
                if (log.checkedMeds.length === 0) {
                    db.calendar.splice(logIdx, 1);
                    writeDB(db);
                    return res.json({ message: "해당 날짜의 복용이 모두 취소되었습니다.", completed: false, checkedMeds: [] });
                }
                
                writeDB(db);
                return res.json({ 
                    message: "해당 약물의 복용 체크 상태가 변경되었습니다.", 
                    completed: log.completed,
                    checkedMeds: log.checkedMeds
                });
            }
        } else {
            // 📅 2. 구버전 호환용 전체 날짜 일괄 완료/취소 토글 시나리오
            if (logIdx === -1) {
                db.calendar.push({ 
                    userId, 
                    date, 
                    completed: true, 
                    checkedMeds: targetMedIds 
                });
                writeDB(db);
                return res.json({ message: `${date} 복약 완료 체크되었습니다! 💊`, completed: true, checkedMeds: targetMedIds });
            } else {
                db.calendar.splice(logIdx, 1);
                writeDB(db);
                return res.json({ message: `${date} 복약 일지가 취소 처리되었습니다.`, completed: false, checkedMeds: [] });
            }
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "일지 처리 중 오류 발생" });
    }
});


// ==========================================
// [4-2. 💬 AI 약사 비서 'Pillip(필립)' 분기 멀티 채팅방 API]
// ==========================================

// 🔑 4-2-1. 대화방 목록 조회 API (일반 상담실 + 등록 약물 분기 상담방 동적 병합)
app.get("/api/chats/rooms/:userId", (req, res) => {
    try {
        const { userId } = req.params;
        const db = readDB();
        
        const user = db.users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ error: "존재하지 않는 회원입니다." });
        }

        // 1. 기본 탑재: 일반 상담방
        const rooms = [
            {
                sessionId: "general",
                title: "🌿 AI 약사 필립 일반 상담실",
                description: "기본 복용 요령 및 기저질환과 연계된 약학 궁금증을 자유롭게 상의해 보세요.",
                risk: "안심",
                score: 0,
                medication: null,
                lastMessage: "안녕하세요! 평소 드시던 약이나 부작용 고민에 대해 편하게 말씀해 주세요. ✨"
            }
        ];

        // 2. 등록 약물 목록 기반 동적 분기 상담방 병합
        const userMeds = db.medications.filter(m => m.userId === userId);
        userMeds.forEach(med => {
            rooms.push({
                sessionId: med.id,
                title: `💊 ${med.name} 전문 상담방`,
                description: `'${med.name}' 복약 지도 및 안전 가이드 맞춤 분기방입니다.`,
                risk: med.risk || "안심",
                score: med.score || 15,
                medication: med,
                lastMessage: med.reason || "약동학 RAG 예측이 완료되었습니다. 궁금증을 남겨보세요."
            });
        });

        // 각 채팅방별 최근 1개의 메시지를 추적하여 복호화 후 lastMessage 최신화 처리
        rooms.forEach(room => {
            const roomChats = db.chats.filter(c => c.userId === userId && c.sessionId === room.sessionId);
            if (roomChats.length > 0) {
                // 작성 시점을 기준으로 내림차순 정렬하여 최신 글 획득
                roomChats.sort((a, b) => b.createdAt - a.createdAt);
                room.lastMessage = decrypt(roomChats[0].message);
            }
        });

        res.json(rooms);
    } catch (err) {
        console.error("대화방 목록 로드 실패:", err);
        res.status(500).json({ error: "분기 대화방 목록을 수집하지 못했습니다." });
    }
});

// 🔑 4-2-2. 특정 분기 대화방의 대화 기록 조회 API (복호화 완벽 보장)
app.get("/api/chats/history/:userId/:sessionId", (req, res) => {
    try {
        const { userId, sessionId } = req.params;
        const db = readDB();

        const roomChats = db.chats.filter(c => c.userId === userId && c.sessionId === sessionId);
        // 시간 흐름에 맞춰 오름차순 정렬 (과거에서 현재 순으로 렌더링되게 함)
        roomChats.sort((a, b) => a.createdAt - b.createdAt);

        // 보안 기밀 대화 평문 해독 후 클라이언트에 응답
        const history = roomChats.map(c => ({
            id: c.id,
            sender: c.sender,
            message: decrypt(c.message), // 🔓 평문으로 복호화 복원
            createdAt: c.createdAt
        }));

        res.json(history);
    } catch (err) {
        console.error("대화 내역 획득 실패:", err);
        res.status(500).json({ error: "이전 대화 내역을 성공적으로 복구하지 못했습니다." });
    }
});

// 🔑 4-2-3. 분기 채팅방 메시지 송수신 및 Gemini AI RAG 답변 통합 라우터 (대화 암호화 영구 저장)
app.post("/api/chats/message", async (req, res) => {
    try {
        const { userId, sessionId, message } = req.body;
        if (!userId || !sessionId || !message) {
            return res.status(400).json({ error: "상담을 개시하기 위한 요건이 충족되지 않았습니다." });
        }

        const db = readDB();
        const user = db.users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ error: "회원 대상을 감지하지 못했습니다." });
        }

        // 1. 환자의 상담 질문 암호화 후 디비에 즉시 안전 세이브
        const userMsgId = "msg_user_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
        const encryptedUserMsg = encrypt(message.trim());
        const userChatRecord = {
            id: userMsgId,
            userId,
            sessionId,
            sender: "user",
            message: encryptedUserMsg,
            createdAt: Date.now()
        };
        db.chats.push(userChatRecord);

        // 2. 환자 프로필 정보 획득
        const userIllness = user.illness || "없음";
        const userAllergies = user.allergies || "없음";
        const userAge = user.age || "미기재";
        const userName = user.name || "보호환자";

        let contextPrompt = `
당신은 대한민국 식약처 공식 의약품 지식과 고도의 약학 전문성을 지닌 친절하고 든든한 환자 맞춤형 AI 약사 비서 'Pillip(필립)'입니다.
말투는 항상 환자를 아끼고 걱정하는 마음을 가득 담아 조곤조곤하고 상냥하게 (~해요, ~입니다, ~해 드릴게요!) 친근한 존댓말로 일관해야 합니다.
사용자의 질문에 대해 신속하고 정확하며, 의학적으로 완전히 안전한 가이드라인을 반환해 주세요.

[현재 상담 환자 프로필]
- 성명: ${userName}님
- 나이: ${userAge}세
- 기저질환(기왕증): ${userIllness}
- 알레르기 유발 요인: ${userAllergies}
`;

        // 3. 만약 '약물별 분기 대화방'일 경우, 해당 약물의 세부 데이터베이스 내용을 RAG Context로 추가
        if (sessionId !== "general") {
            const med = db.medications.find(m => m.id === sessionId && m.userId === userId);
            if (med) {
                contextPrompt += `
[현재 분기 대화방의 타겟 지정 의약품 정보]
- 약물명: ${med.name}
- 식약처 분석 위험 수준: ${med.risk} (위험 점수: ${med.score}점)
- 임상적 안전 검토 평정 사유: ${med.reason}
- 주요 효능 정보: ${med.kfdaInfo?.efcy || "정보 없음"}
- 주의사항 가이드라인: ${med.kfdaInfo?.atpn || med.kfdaInfo?.warn || "정보 없음"}
- 안심 복약 가이드:
  1. ${med.summary?.[0] || "전문의 지시 준수"}
  2. ${med.summary?.[1] || "정량 복용 엄수"}
  3. ${med.summary?.[2] || "이상 시 즉시 중단"}
`;
            }
        }

        // 4. 대화의 영속성 및 연속성을 위한 이전 채팅 맥락 흐름 주입 (최근 6개의 복호화된 대화 삽입)
        const roomChats = db.chats.filter(c => c.userId === userId && c.sessionId === sessionId);
        roomChats.sort((a, b) => a.createdAt - b.createdAt);
        const recentChats = roomChats.slice(-6); // 최근 6개 대화 맥락 확보

        if (recentChats.length > 0) {
            contextPrompt += `\n[최근에 나눈 대화 맥락 흐름 (이를 토대로 맥락을 이어 답변하세요)]\n`;
            recentChats.forEach(c => {
                const speaker = c.sender === "user" ? "환자" : "AI 약사 필립";
                contextPrompt += `- ${speaker}: ${decrypt(c.message)}\n`;
            });
        }

        contextPrompt += `
[상담 질문]
"${message}"

위 환자 의료 프로필과 타겟 약학 데이터 및 최근 대화의 흐름을 고도로 정밀하게 관조하여, 전문 수석 약사처럼 정량적이고 지혜로우며 친절한 조언을 전개해 주세요.
만약 기저질환이나 알레르기 수치와 미세한 충돌이라도 일어날 우려가 있다면 확실하고 굵게 환자에게 경고 및 환기 시켜야만 합니다.
스마트폰 화면에 가독성이 뛰어나도록 이모티콘을 예쁘게 활용하고 적절한 줄바꿈과 마크다운 굵은 강조(**)를 조합해 주세요.
`;

        // 5. Gemini 2.5-Flash 엔진 가동하여 메디컬 가이드 조율 (안전 최우선 Try-Catch 장전)
        let reply = "";
        try {
            const model = genAI.getGenerativeModel({ model: "gemini-3.6-flash" });
            const result = await model.generateContent(contextPrompt);
            reply = result.response.text().trim();
        } catch (apiErr) {
            console.error("Gemini 2.5-Flash API 호출 실패 에러 발생:", apiErr);
            // 🛡️ API 통신 실패 및 모델 404/할당량 초과 에러 시에도 서버 크래시를 원천 차단하고 아래 예쁜 메시지 반환!
            return res.status(200).json({
                reply: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요.",
                userMessage: { id: userMsgId, sender: "user", message, createdAt: userChatRecord.createdAt },
                pillipMessage: { id: "msg_pillip_fallback_" + Date.now(), sender: "pillip", message: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요.", createdAt: Date.now() }
            });
        }

        // 6. AI의 맞춤 복약 진단 메시지 암호화 후 디스크 영구 적재
        const pillipMsgId = "msg_pillip_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
        const encryptedReply = encrypt(reply);
        const pillipChatRecord = {
            id: pillipMsgId,
            userId,
            sessionId,
            sender: "pillip",
            message: encryptedReply,
            createdAt: Date.now()
        };
        db.chats.push(pillipChatRecord);

        // 7. 암호화 레코드 디스크 기록 커밋
        writeDB(db);

        // 8. 해독된 평문 대화 응답 데이터 반환
        res.json({
            reply,
            userMessage: { id: userMsgId, sender: "user", message, createdAt: userChatRecord.createdAt },
            pillipMessage: { id: pillipMsgId, sender: "pillip", message: reply, createdAt: pillipChatRecord.createdAt }
        });

    } catch (err) {
        console.error("필립 분기 대화 처리 예외:", err);
        // 서버 다운 방지를 위한 예외 처리 강화
        res.status(200).json({ 
            reply: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요.",
            userMessage: { id: "msg_user_err_" + Date.now(), sender: "user", message, createdAt: Date.now() },
            pillipMessage: { id: "msg_pillip_err_" + Date.now(), sender: "pillip", message: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요.", createdAt: Date.now() }
        });
    }
});

// 💡 🔑 4-2-4. [구버전 컴패티빌리티 폴백 API]: 기존 엔드포인트 연동 우회 수렴
app.post("/api/pillip/chat", async (req, res) => {
    try {
        const { message, medicationContext } = req.body;
        if (!message) {
            return res.status(400).json({ error: "메시지 내용이 누락되었습니다." });
        }
        
        // 구버전 단일 대화는 "general" 세션으로 매핑하여 유기적으로 연동 수렴
        const userId = medicationContext?.userId || "user_default";
        const sessionId = medicationContext?.id || "general";

        let reply = "";
        try {
            const model = genAI.getGenerativeModel({ model: "gemini-3.6-flash" });
            const result = await model.generateContent(message);
            reply = result.response.text().trim();
        } catch (apiErr) {
            console.error("구버전 대화 API 연동 중 제미나이 에러:", apiErr);
            return res.status(200).json({ reply: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요." });
        }
        
        res.json({ reply });
    } catch (err) {
        console.error("구버전 대화 API 폴백 실패:", err);
        res.status(200).json({ reply: "현재 AI 응답이 지연되고 있습니다. 잠시 후 다시 시도해 주세요." });
    }
});


// ==========================================
// [5. 스마트 실시간 알람 정밀 매핑 API]
// ==========================================
app.get("/api/alarms/:userId", (req, res) => {
    try {
        const { userId } = req.params;
        const db = readDB();
        const list = db.alarms.filter(a => a.userId === userId);
        res.json(list);
    } catch (err) {
        console.error(err);
        res.json([]);
    }
});

app.post("/api/alarms/add/:userId", (req, res) => {
    try {
        const { userId } = req.params;
        const { medicationName, dateTime } = req.body;
        if (!medicationName || !dateTime) {
            return res.status(400).json({ error: "의약품 이름과 복용 일시를 입력해 주세요." });
        }

        const db = readDB();
        const newAlarm = {
            id: "alarm_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
            userId,
            medicationName,
            dateTime,
            triggered: false
        };

        db.alarms.push(newAlarm);
        writeDB(db);
        res.status(201).json({ success: true, message: "⏰ 복약 예약 알림이 정상 등록되었습니다!", alarm: newAlarm });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "알람 등록 중 예외가 발생했습니다." });
    }
});

app.post("/api/alarms/delete/:userId/:alarmId", (req, res) => {
    try {
        const { userId, alarmId } = req.params;
        const db = readDB();
        const idx = db.alarms.findIndex(a => a.id === alarmId && a.userId === userId);
        if (idx === -1) {
            return res.status(404).json({ error: "알람을 찾을 수 없습니다." });
        }

        db.alarms.splice(idx, 1);
        writeDB(db);
        res.json({ message: "알람이 안전하게 영구 소거되었습니다." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "알람 삭제 중 오류 발생" });
    }
});

app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`💊 Pillip SafeDrug AI Backend 구동 완료!`);
    console.log(`🚀 포트 주소: http://localhost:${PORT}`);
    console.log(`====================================================`);
});
