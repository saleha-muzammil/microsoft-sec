const pptxgen = require("pptxgenjs");
const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";           // 13.3 x 7.5
pres.author = "SCuBA Compliance Copilot";
pres.title = "SCuBA Compliance Copilot";

const NAVY="0A1A2F", NAVY2="14304F", TEAL="00A896", CYAN="3FC1C9",
      AMBER="FFB700", RED="E5484D", GREEN="30A46C",
      LIGHT="F4F7F9", WHITE="FFFFFF", GREY="5A6B7B", INK="10212F";

const H="Cambria", B="Calibri";

// ---------- helpers (fresh objects each call; pptxgenjs mutates options) ----------
const darkBg = () => ({ color: NAVY });
const lightBg = () => ({ color: WHITE });

function title(s, text, opts={}) {
  s.addText(text, { isTextBox:true, x:0.7, y:opts.y??0.45, w:11.9, h:0.9,
    fontFace:H, fontSize:opts.size??34, bold:true,
    color:opts.color??INK, align:"left", margin:0 });
}
function kicker(s, text, color) {
  s.addText(text, { isTextBox:true, x:0.7, y:0.2, w:11.9, h:0.32, fontFace:B,
    fontSize:12, bold:true, color:color??TEAL, charSpacing:2, margin:0 });
}
function note(s, t){ s.addNotes(t); }

// stat card
function stat(s, x, y, w, value, label, valColor, bg) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h:1.65, fill:{color:bg??LIGHT},
    rectRadius:0.1, line:{ color: bg??LIGHT } });
  s.addText(value, { isTextBox:true, x, y:y+0.18, w, h:0.82, fontFace:B, fontSize:40,
    bold:true, color:valColor??INK, align:"center", margin:0 });
  s.addText(label, { isTextBox:true, x:x+0.12, y:y+1.0, w:w-0.24, h:0.55, fontFace:B,
    fontSize:11.5, color:GREY, align:"center", margin:0 });
}

// ============================ 1. TITLE ============================
{
  const s = pres.addSlide(); s.background = darkBg();
  s.addShape(pres.ShapeType.ellipse, { x:10.6, y:-1.5, w:5.2, h:5.2,
    fill:{ color: NAVY2 } });
  s.addShape(pres.ShapeType.ellipse, { x:11.9, y:5.4, w:2.8, h:2.8,
    fill:{ color: NAVY2 } });

  s.addText("MICROSOFT & CCI INNOVATION CHALLENGE FOR VIRGINIA", { isTextBox:true,
    x:0.9, y:1.5, w:11, h:0.35, fontFace:B, fontSize:12, bold:true, color:CYAN,
    charSpacing:2, margin:0 });
  s.addText("SCuBA Compliance Copilot", { isTextBox:true, x:0.9, y:2.0, w:11.2, h:1.1,
    fontFace:H, fontSize:52, bold:true, color:WHITE, margin:0 });
  s.addText("Turning CISA's SCuBA baselines and ScubaGear assessments into validated OSCAL —\nwith an AI layer that cannot invent a compliance fact.",
    { isTextBox:true, x:0.9, y:3.15, w:10.6, h:1.0, fontFace:B, fontSize:17,
      color:"C6D4E0", lineSpacing:26, margin:0 });

  s.addText("Challenge: SCuBA Security Application — OSCAL-based representation of SCuBA baseline content and assessment results",
    { isTextBox:true, x:0.9, y:4.45, w:11, h:0.4, fontFace:B, fontSize:11.5,
      italic:true, color:CYAN, margin:0 });

  [["8","OSCAL documents"],["100%","eval accuracy"],["26","false findings eliminated"]]
    .forEach(([v,l],i)=>{
      const x = 0.9 + i*3.5;
      s.addText(v, { isTextBox:true, x, y:5.25, w:3.2, h:0.6, fontFace:B, fontSize:32,
        bold:true, color:AMBER, margin:0 });
      s.addText(l, { isTextBox:true, x, y:5.85, w:3.2, h:0.35, fontFace:B, fontSize:12,
        color:"9FB3C8", margin:0 });
    });

  s.addText("Virginia Tech  ·  University of Virginia", { isTextBox:true, x:0.9, y:6.7,
    w:11, h:0.35, fontFace:B, fontSize:12, color:"7E93A6", margin:0 });
  note(s,"Opening. We took the SCuBA/OSCAL challenge. Three numbers to remember: eight validated OSCAL documents, 100% eval accuracy, and 26 false findings that existing approaches produce and we eliminate.");
}

// ============================ 2. PROBLEM ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"THE PROBLEM");
  title(s,"Compliance stops where the scanner ends");

  s.addText([
    { text:"CISA publishes SCuBA", options:{ bold:true, breakLine:false } },
    { text:" — the secure configuration baselines for Microsoft 365 — and ", options:{ breakLine:false } },
    { text:"ScubaGear", options:{ bold:true, breakLine:false } },
    { text:", a scanner that grades a tenant against them.", options:{ breakLine:true } },
  ], { isTextBox:true, x:0.7, y:1.5, w:7.2, h:0.8, fontFace:B, fontSize:15,
       color:INK, lineSpacing:24, margin:0 });

  s.addText("But ScubaGear produces a report for a human to read — not machine-readable compliance evidence.",
    { isTextBox:true, x:0.7, y:2.35, w:7.2, h:0.6, fontFace:B, fontSize:15, color:INK,
      lineSpacing:24, margin:0 });

  s.addText("So everything downstream is still done by hand:", { isTextBox:true, x:0.7,
    y:3.1, w:7.2, h:0.35, fontFace:B, fontSize:14, bold:true, color:INK, margin:0 });

  s.addText([
    { text:"System Security Plans, written in Word", options:{ bullet:true, breakLine:true } },
    { text:"Plans of Action & Milestones, tracked in spreadsheets", options:{ bullet:true, breakLine:true } },
    { text:"NIST 800-53 mappings, assembled manually for ATO packages", options:{ bullet:true, breakLine:true } },
    { text:"Auditor questions, answered by re-reading the report", options:{ bullet:true, breakLine:false } },
  ], { isTextBox:true, x:0.9, y:3.55, w:7.0, h:1.7, fontFace:B, fontSize:14,
       color:INK, paraSpaceAfter:8, margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:8.4, y:1.5, w:4.2, h:3.9,
    fill:{ color:NAVY }, rectRadius:0.1, line:{ color:NAVY } });
  s.addText("BOD 25-01", { isTextBox:true, x:8.6, y:1.85, w:3.8, h:0.5, fontFace:B,
    fontSize:26, bold:true, color:AMBER, align:"center", margin:0 });
  s.addText("CISA Binding Operational Directive", { isTextBox:true, x:8.6, y:2.35, w:3.8,
    h:0.35, fontFace:B, fontSize:11, color:CYAN, align:"center", margin:0 });
  s.addText("These baselines are not best practice.\n\nThey are legally mandatory for federal civilian agencies — and the de facto standard for the universities, school divisions and local governments running the same Microsoft 365 estate.",
    { isTextBox:true, x:8.7, y:2.85, w:3.6, h:2.3, fontFace:B, fontSize:12.5,
      color:"D8E3EC", lineSpacing:19, margin:0 });

  s.addText("An organisation without a dedicated GRC team needs weeks to get from “we ran the scanner” to “we have an auditable package.”",
    { isTextBox:true, x:0.7, y:5.55, w:11.9, h:0.5, fontFace:B, fontSize:14.5,
      italic:true, bold:true, color:NAVY2, margin:0 });
  note(s,"The gap is not detection — CISA solved that. The gap is everything after detection. And BOD 25-01 makes it mandatory, so this work is not optional.");
}

// ============================ 3. THE GAP / PRIOR ART ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"THE OPENING");
  title(s,"CISA started this bridge — and stopped");

  s.addShape(pres.ShapeType.roundRect, { x:0.7, y:1.5, w:11.9, h:1.65,
    fill:{ color:"FFF6E0" }, rectRadius:0.1, line:{ color:"FFE2A8" } });
  s.addText("“you can't have an assessment plan model without implementing all the preceeding layers”",
    { isTextBox:true, x:1.0, y:1.72, w:11.3, h:0.5, fontFace:H, fontSize:18,
      italic:true, bold:true, color:INK, margin:0 });
  s.addText("— README of ScubaGear's  oscal-exploration  branch · last commit August 2024 · never merged",
    { isTextBox:true, x:1.0, y:2.25, w:11.3, h:0.32, fontFace:B, fontSize:12,
      color:GREY, margin:0 });
  s.addText("Component-definition, SSP and POA&M are left marked TODO.",
    { isTextBox:true, x:1.0, y:2.62, w:11.3, h:0.35, fontFace:B, fontSize:13.5,
      bold:true, color:"8A5A00", margin:0 });

  s.addText("We verified the landscape before claiming anything", { isTextBox:true, x:0.7,
    y:3.45, w:11.9, h:0.4, fontFace:B, fontSize:16, bold:true, color:INK, margin:0 });

  const rows = [
    ["Exists already", "A dead 2024 proof-of-concept catalog. Drift tools that match on policy ID. AI-over-OSCAL assistants.", GREY],
    ["Does NOT exist", "A complete, maintained M365 chain from catalog through POA&M — with mappings provably faithful to CISA's own crosswalk.", GREEN],
  ];
  rows.forEach(([h,t,c],i)=>{
    const y = 3.95 + i*1.0;
    s.addShape(pres.ShapeType.roundRect, { x:0.7, y, w:2.3, h:0.85,
      fill:{ color: i? "E8F6EF" : LIGHT }, rectRadius:0.08, line:{ color: i? "C3E9D7" : "E2E8EE" } });
    s.addText(h, { isTextBox:true, x:0.7, y:y+0.26, w:2.3, h:0.35, fontFace:B,
      fontSize:13, bold:true, color:c, align:"center", margin:0 });
    s.addText(t, { isTextBox:true, x:3.2, y:y+0.08, w:9.4, h:0.75, fontFace:B,
      fontSize:13.5, color:INK, lineSpacing:19, margin:0 });
  });

  s.addText("So we make precise claims, not “first ever” claims — a subject-matter judge would puncture those, and several are already taken.",
    { isTextBox:true, x:0.7, y:6.1, w:11.9, h:0.45, fontFace:B, fontSize:13,
      italic:true, color:GREY, margin:0 });
  note(s,"We researched prior art first. CISA tried this and abandoned it. That is our opening, and it is evidenced by their own README rather than asserted by us.");
}

// ============================ 4. ARCHITECTURE ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"ARCHITECTURE");
  title(s,"Deterministic core. AI on top. Never the reverse.");

  const boxes = [
    ["INPUT", ["CISA SCuBA baselines\n127 policies","CISA ScubaGear run\n92 assessed checks","CISA crosswalk +\nmigration table"], LIGHT, INK, "E2E8EE"],
  ];
  boxes[0][1].forEach((t,i)=>{
    s.addShape(pres.ShapeType.roundRect, { x:0.7, y:1.55+i*0.92, w:3.1, h:0.78,
      fill:{color:LIGHT}, rectRadius:0.08, line:{color:"E2E8EE"} });
    s.addText(t, { isTextBox:true, x:0.8, y:1.62+i*0.92, w:2.9, h:0.64, fontFace:B,
      fontSize:11.5, color:INK, align:"center", lineSpacing:15, margin:0 });
  });
  s.addText("PUBLIC CISA DATA  ·  CC0", { isTextBox:true, x:0.7, y:4.35, w:3.1, h:0.3,
    fontFace:B, fontSize:9.5, bold:true, color:GREY, align:"center", charSpacing:1, margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:4.3, y:1.55, w:3.5, h:2.58,
    fill:{color:NAVY2}, rectRadius:0.1, line:{color:NAVY2} });
  s.addText("Typed Python\nparsers + transformers", { isTextBox:true, x:4.45, y:1.75, w:3.2,
    h:0.7, fontFace:B, fontSize:14, bold:true, color:WHITE, align:"center", lineSpacing:19, margin:0 });
  s.addText("No model decides what a control ID is,\nwhat a result was, or what belongs in a\nrequired schema field.",
    { isTextBox:true, x:4.45, y:2.5, w:3.2, h:0.9, fontFace:B, fontSize:11,
      color:"BBD0E2", align:"center", lineSpacing:16, margin:0 });
  s.addText("59 tests", { isTextBox:true, x:4.45, y:3.5, w:3.2, h:0.4, fontFace:B,
    fontSize:15, bold:true, color:CYAN, align:"center", margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:8.3, y:1.55, w:4.3, h:1.2,
    fill:{color:"0E3B2E"}, rectRadius:0.1, line:{color:"0E3B2E"} });
  s.addText("8 OSCAL 1.2.3 documents", { isTextBox:true, x:8.45, y:1.72, w:4.0, h:0.4,
    fontFace:B, fontSize:14.5, bold:true, color:WHITE, align:"center", margin:0 });
  s.addText("validated by NIST oscal-cli\nwith full Metaschema constraints", { isTextBox:true,
    x:8.45, y:2.12, w:4.0, h:0.55, fontFace:B, fontSize:11, color:"9FE3C4",
    align:"center", lineSpacing:15, margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:8.3, y:2.93, w:4.3, h:1.2,
    fill:{color:"0B3552"}, rectRadius:0.1, line:{color:"0B3552"} });
  s.addText("Microsoft Foundry agents", { isTextBox:true, x:8.45, y:3.1, w:4.0, h:0.4,
    fontFace:B, fontSize:14.5, bold:true, color:WHITE, align:"center", margin:0 });
  s.addText("posture · risk · remediation · report", { isTextBox:true, x:8.45, y:3.5,
    w:4.0, h:0.3, fontFace:B, fontSize:11, color:CYAN, align:"center", margin:0 });
  s.addText("reach facts ONLY through tool calls", { isTextBox:true, x:8.45, y:3.78,
    w:4.0, h:0.3, fontFace:B, fontSize:10.5, italic:true, color:"9FB3C8", align:"center", margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:0.7, y:4.85, w:11.9, h:1.5,
    fill:{color:"F0F6FB"}, rectRadius:0.1, line:{color:"D4E4F0"} });
  s.addText("Why this ordering is the whole design", { isTextBox:true, x:1.0, y:5.02, w:11.3,
    h:0.35, fontFace:B, fontSize:14, bold:true, color:NAVY, margin:0 });
  s.addText("“How do you know the model didn't invent that number?”  —  It couldn't have. Every figure comes from a pure function over a document that passed the NIST validator, and that function has tests.",
    { isTextBox:true, x:1.0, y:5.42, w:11.3, h:0.8, fontFace:B, fontSize:13.5,
      color:INK, lineSpacing:20, margin:0 });
  note(s,"The single most important decision: parsing and OSCAL generation are plain typed Python. AI is layered on top where judgement helps, and is structurally prevented from touching the facts.");
}

// ============================ 5. THE OSCAL CHAIN ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"RESULT #1  ·  PERFORMANCE");
  title(s,"The complete OSCAL chain — all eight validate");

  const rows = [
    ["catalog","127 SCuBA policies, rationale, guidance, MITRE ATT&CK"],
    ["profile","the controls this assessment covered"],
    ["component-definition","the M365 services under assessment", true],
    ["system-security-plan","the tenant and its in-scope controls", true],
    ["assessment-plan","the procedure ScubaGear performs"],
    ["assessment-results","92 observations · 83 findings · 26 risks"],
    ["plan-of-action-and-milestones","26 prioritised items with deadlines", true],
    ["mapping-collection","SCuBA → NIST 800-53, with provenance"],
  ];
  rows.forEach(([m,d,isNew],i)=>{
    const y = 1.5 + i*0.6;
    s.addShape(pres.ShapeType.roundRect, { x:0.7, y, w:11.1, h:0.5,
      fill:{ color: i%2 ? WHITE : LIGHT }, rectRadius:0.05,
      line:{ color: i%2 ? "EDF1F4" : "E2E8EE" } });
    s.addText("✓", { isTextBox:true, x:0.85, y:y+0.08, w:0.35, h:0.35, fontFace:B,
      fontSize:14, bold:true, color:GREEN, align:"center", margin:0 });
    s.addText(m, { isTextBox:true, x:1.3, y:y+0.1, w:3.4, h:0.32, fontFace:B,
      fontSize:12.5, bold:true, color:INK, margin:0 });
    s.addText(d, { isTextBox:true, x:4.8, y:y+0.1, w:5.6, h:0.32, fontFace:B,
      fontSize:12, color:GREY, margin:0 });
    if (isNew) {
      s.addShape(pres.ShapeType.roundRect, { x:10.5, y:y+0.09, w:1.15, h:0.32,
        fill:{color:"FFF1CC"}, rectRadius:0.05, line:{color:"FFE2A8"} });
      s.addText("CISA TODO", { isTextBox:true, x:10.5, y:y+0.13, w:1.15, h:0.26,
        fontFace:B, fontSize:8.5, bold:true, color:"8A5A00", align:"center", margin:0 });
    }
  });

  s.addText("Validated with NIST's own oscal-cli 3.2.0 / liboscal-java 7.2.0 — full Metaschema constraints, not merely JSON Schema. Zero errors, zero warnings, enforced in CI.",
    { isTextBox:true, x:0.7, y:6.4, w:11.9, h:0.5, fontFace:B, fontSize:13,
      bold:true, color:NAVY2, lineSpacing:19, margin:0 });
  note(s,"Three of these — component-definition, SSP and POA&M — are the ones CISA marked TODO. Passing JSON Schema is necessary but not sufficient; Metaschema enforces cardinality and cross-reference resolution too.");
}

// ============================ 6. MAPPING PROVENANCE ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"RESULT #2  ·  INNOVATION");
  title(s,"Mappings provably faithful to CISA");

  s.addText("CISA already publishes the authoritative SCuBA → NIST 800-53 crosswalk. Asking a model to guess what CISA has already stated is not innovation — it is a correctness regression.",
    { isTextBox:true, x:0.7, y:1.45, w:11.9, h:0.65, fontFace:B, fontSize:14.5,
      color:INK, lineSpacing:21, margin:0 });

  stat(s, 0.7, 2.3, 2.75, "71", "direct crosswalk entries", INK);
  stat(s, 3.65, 2.3, 2.75, "+18", "resolved via CISA's\nmigration table", INK);
  stat(s, 6.6, 2.3, 2.75, "89/92", "deterministic — 97%\nzero AI guessing", GREEN, "E8F6EF");
  stat(s, 9.55, 2.3, 3.05, "3", "reported as unmapped:\nnever inferred", "8A5A00", "FFF6E0");

  s.addShape(pres.ShapeType.roundRect, { x:0.7, y:4.3, w:11.9, h:1.5,
    fill:{color:NAVY}, rectRadius:0.1, line:{color:NAVY} });
  s.addText("The CI test that proves it", { isTextBox:true, x:1.0, y:4.48, w:11.3, h:0.35,
    fontFace:B, fontSize:14, bold:true, color:AMBER, margin:0 });
  s.addText("Our build fails if any emitted mapping diverges from CISA's CSV — read independently of our own parser, so a parser bug cannot make the test agree with itself. It also pins a case published third-party tooling gets wrong:",
    { isTextBox:true, x:1.0, y:4.85, w:11.3, h:0.55, fontFace:B, fontSize:12.5,
      color:"D2DEE8", lineSpacing:18, margin:0 });
  s.addText("MS.AAD.1.1v1  →  CM-7  (least functionality)          not  IA-2(1)  (an MFA control)",
    { isTextBox:true, x:1.0, y:5.38, w:11.3, h:0.32, fontFace:"Courier New", fontSize:12.5,
      bold:true, color:CYAN, margin:0 });

  s.addText("Emitted as an OSCAL 1.2 mapping-collection — where provenance, confidence-score and matching-rationale are native fields, so the distinction lives in the standard rather than a convention we invented.",
    { isTextBox:true, x:0.7, y:6.0, w:11.9, h:0.6, fontFace:B, fontSize:12.5,
      italic:true, color:GREY, lineSpacing:18, margin:0 });
  note(s,"This is the difference between a tool you can audit and one you have to trust. 91% deterministic, and the remaining 8 are clearly labelled as AI proposals requiring human approval.");
}

// ============================ 7. DRIFT ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"RESULT #3  ·  INNOVATION");
  title(s,"Drift that survives a baseline version change");

  s.addText("SCuBA policy IDs are versioned, and CISA revises them. Between two runs, MS.DEFENDER.* became MS.SECURITYSUITE.*. A tool matching on identifier reports each renumbered policy twice — once vanished, once new.",
    { isTextBox:true, x:0.7, y:1.42, w:11.9, h:0.65, fontFace:B, fontSize:14,
      color:INK, lineSpacing:20, margin:0 });

  s.addChart(pres.ChartType.bar, [
    { name:"Matching by identifier", labels:["Phantom\nnew findings","Phantom\nresolved findings","Renumberings\nrecognised"], values:[13,13,0] },
    { name:"Version-aware (ours)",    labels:["Phantom\nnew findings","Phantom\nresolved findings","Renumberings\nrecognised"], values:[0,0,13] },
  ], { x:0.7, y:2.2, w:7.3, h:3.4, barDir:"col", barGrouping:"clustered",
       chartColors:[RED, GREEN], showLegend:true, legendPos:"b", legendFontSize:11,
       showValue:true, dataLabelPosition:"outEnd", dataLabelFontSize:12,
       dataLabelFontBold:true, catAxisLabelFontSize:10, valAxisLabelFontSize:10,
       catAxisLabelColor:GREY, valAxisLabelColor:GREY,
       valGridLine:{ color:"EDF1F4", size:1 }, catGridLine:{ style:"none" },
       valAxisMaxVal:16 });

  s.addShape(pres.ShapeType.roundRect, { x:8.3, y:2.2, w:4.3, h:1.75,
    fill:{color:"FDECEC"}, rectRadius:0.1, line:{color:"F7C9C9"} });
  s.addText("26", { isTextBox:true, x:8.3, y:2.35, w:4.3, h:0.75, fontFace:B, fontSize:52,
    bold:true, color:RED, align:"center", margin:0 });
  s.addText("fabricated events from a single\nbaseline renumbering", { isTextBox:true,
    x:8.5, y:3.1, w:3.9, h:0.65, fontFace:B, fontSize:12.5, color:"8A2A2A",
    align:"center", lineSpacing:17, margin:0 });

  s.addText("What actually changed", { isTextBox:true, x:8.3, y:4.12, w:4.3, h:0.32,
    fontFace:B, fontSize:13, bold:true, color:INK, margin:0 });
  s.addText([
    { text:"3 genuine improvements", options:{ bullet:true, breakLine:true, color:GREEN } },
    { text:"1 genuine regression", options:{ bullet:true, breakLine:true, color:RED } },
    { text:"13 renumberings, correctly absorbed", options:{ bullet:true, breakLine:false, color:GREY } },
  ], { isTextBox:true, x:8.45, y:4.5, w:4.1, h:1.1, fontFace:B, fontSize:12.5,
       paraSpaceAfter:5, margin:0 });

  s.addText("This corrupts exactly the numbers a compliance report is built on: how many findings opened, how many closed, whether posture improved. CISA publishes the fix themselves — we consume it.",
    { isTextBox:true, x:0.7, y:5.9, w:11.9, h:0.6, fontFace:B, fontSize:13,
      bold:true, color:NAVY2, lineSpacing:19, margin:0 });
  note(s,"This is a real technical insight, not a feature list item. Every drift tool we found compares run-to-run by ID and would get this wrong.");
}

// ============================ 8. AI LAYER ============================
{
  const s = pres.addSlide(); s.background = darkBg();
  kicker(s,"MICROSOFT FOUNDRY", CYAN);
  title(s,"An AI layer that cannot fabricate", { color:WHITE });

  s.addText("question  →  agent  →  tool call  →  NIST-validated OSCAL  →  answer",
    { isTextBox:true, x:0.7, y:1.5, w:11.9, h:0.45, fontFace:"Courier New", fontSize:15,
      bold:true, color:CYAN, margin:0 });
  s.addText("There is no other path to a fact.", { isTextBox:true, x:0.7, y:1.95, w:11.9,
    h:0.35, fontFace:B, fontSize:13, italic:true, color:"9FB3C8", margin:0 });

  const agents = [
    ["Posture","current state, and what a policy requires"],
    ["Risk","ranks by SHALL/SHOULD, ATT&CK breadth, blast radius"],
    ["Remediation","fixes grounded in CISA's own guidance"],
    ["Report","executive · auditor · engineer phrasing"],
  ];
  agents.forEach(([n,d],i)=>{
    const x = 0.7 + i*3.0;
    s.addShape(pres.ShapeType.roundRect, { x, y:2.5, w:2.8, h:1.5, fill:{color:NAVY2},
      rectRadius:0.1, line:{color:"1E4468"} });
    s.addText(n, { isTextBox:true, x:x+0.15, y:2.65, w:2.5, h:0.35, fontFace:B,
      fontSize:15, bold:true, color:CYAN, margin:0 });
    s.addText(d, { isTextBox:true, x:x+0.15, y:3.02, w:2.5, h:0.85, fontFace:B,
      fontSize:11.5, color:"C6D4E0", lineSpacing:16, margin:0 });
  });

  s.addText("Guardrails that are mechanisms, not promises", { isTextBox:true, x:0.7, y:4.25,
    w:11.9, h:0.35, fontFace:B, fontSize:15, bold:true, color:WHITE, margin:0 });
  s.addText([
    { text:"Unknown policy IDs return an error — never a plausible-looking control", options:{ bullet:true, breakLine:true } },
    { text:"Every mapping reports provenance; an AI proposal can never override CISA", options:{ bullet:true, breakLine:true } },
    { text:"Untestable policies recorded as EXAMINE, not TEST — evidence is never overstated", options:{ bullet:true, breakLine:true } },
    { text:"AI-authored remediation prose tagged generated-by=ai-assistant inside the POA&M", options:{ bullet:true, breakLine:false } },
  ], { isTextBox:true, x:0.9, y:4.68, w:11.5, h:1.6, fontFace:B, fontSize:13,
       color:"D2DEE8", paraSpaceAfter:7, margin:0 });

  s.addText("gpt-5-mini on Microsoft Foundry  ·  keyless auth  ·  Microsoft Agent Framework",
    { isTextBox:true, x:0.7, y:6.55, w:11.9, h:0.35, fontFace:B, fontSize:12,
      color:"7E93A6", margin:0 });
  note(s,"Four specialists share one grounding rule. The guardrails are architectural: agents have no access to data, only to tools that read validated documents.");
}

// ============================ 9. EVALUATION ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"MEASURED, NOT ASSERTED");
  title(s,"Evaluation against a golden set");

  stat(s, 0.7, 1.5, 2.9, "100%", "accuracy\n15 / 15 cases", GREEN, "E8F6EF");
  stat(s, 3.8, 1.5, 2.9, "100%", "citation rate\nwhere one is required", GREEN, "E8F6EF");
  stat(s, 6.9, 1.5, 2.9, "9.9s", "median latency\np95 19.4s", INK);
  stat(s, 10.0, 1.5, 2.6, "59", "unit tests\nall passing", INK);

  s.addText("The probes that matter most", { isTextBox:true, x:0.7, y:3.4, w:6.0, h:0.35,
    fontFace:B, fontSize:15, bold:true, color:INK, margin:0 });
  s.addText([
    { text:"Asked what MS.FAKE.9.9v9 requires → refuses, rather than inventing a control", options:{ bullet:true, breakLine:true } },
    { text:"Asked to map an unmapped policy → reports it as unmapped, not a guess", options:{ bullet:true, breakLine:true } },
    { text:"Returns CISA's CM-7 and never the IA-2(1) other tooling gets wrong", options:{ bullet:true, breakLine:false } },
  ], { isTextBox:true, x:0.9, y:3.82, w:5.9, h:1.5, fontFace:B, fontSize:12.5,
       color:INK, paraSpaceAfter:7, margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:7.1, y:3.4, w:5.5, h:2.6,
    fill:{color:"FFF6E0"}, rectRadius:0.1, line:{color:"FFE2A8"} });
  s.addText("The evaluation earned its place", { isTextBox:true, x:7.35, y:3.58, w:5.0,
    h:0.35, fontFace:B, fontSize:13.5, bold:true, color:"8A5A00", margin:0 });
  s.addText("It caught a real defect in our own prompt design. The report agent wrote “a substantial set of policies passed” — no numbers at all.\n\nRoot cause: our own grounding rule. Telling a model never to state an ungrounded fact made vagueness feel like the safe option.\n\nNaming that failure mode explicitly moved the suite from 14/15 to 15/15.",
    { isTextBox:true, x:7.35, y:3.98, w:5.0, h:1.9, fontFace:B, fontSize:11.5,
      color:INK, lineSpacing:16, margin:0 });

  s.addText("Ground truth is derived from the generated artifacts, so the question set cannot drift away from the data it describes.",
    { isTextBox:true, x:0.7, y:6.2, w:11.9, h:0.4, fontFace:B, fontSize:12.5,
      italic:true, color:GREY, margin:0 });
  note(s,"We report the miss as well as the score. The eval found a bug we introduced, we fixed the cause rather than the test, and both changes are in the commit history.");
}

// ============================ 10. IMPACT ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"ECONOMIC VALUE & SOCIETAL IMPACT");
  title(s,"Built for the institutions that can least afford this work");

  s.addShape(pres.ShapeType.roundRect, { x:0.7, y:1.45, w:5.8, h:2.2,
    fill:{color:LIGHT}, rectRadius:0.1, line:{color:"E2E8EE"} });
  s.addText("Today, by hand", { isTextBox:true, x:0.95, y:1.62, w:5.3, h:0.35, fontFace:B,
    fontSize:14, bold:true, color:GREY, margin:0 });
  s.addText([
    { text:"Read the ScubaGear report", options:{ bullet:true, breakLine:true } },
    { text:"Transcribe failures into a POA&M spreadsheet", options:{ bullet:true, breakLine:true } },
    { text:"Look up each NIST 800-53 mapping", options:{ bullet:true, breakLine:true } },
    { text:"Write the SSP in Word", options:{ bullet:true, breakLine:false } },
  ], { isTextBox:true, x:1.1, y:2.02, w:5.1, h:1.45, fontFace:B, fontSize:12.5,
       color:INK, paraSpaceAfter:6, margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:6.8, y:1.45, w:5.8, h:2.2,
    fill:{color:"E8F6EF"}, rectRadius:0.1, line:{color:"C3E9D7"} });
  s.addText("With this pipeline", { isTextBox:true, x:7.05, y:1.62, w:5.3, h:0.35,
    fontFace:B, fontSize:14, bold:true, color:GREEN, margin:0 });
  s.addText([
    { text:"One command, seconds", options:{ bullet:true, breakLine:true } },
    { text:"POA&M generated with severity and deadlines", options:{ bullet:true, breakLine:true } },
    { text:"Mappings bound to CISA's crosswalk", options:{ bullet:true, breakLine:true } },
    { text:"SSP in the format assessors already consume", options:{ bullet:true, breakLine:false } },
  ], { isTextBox:true, x:7.2, y:2.02, w:5.1, h:1.45, fontFace:B, fontSize:12.5,
       color:INK, paraSpaceAfter:6, margin:0 });

  s.addShape(pres.ShapeType.roundRect, { x:0.7, y:3.9, w:11.9, h:1.55,
    fill:{color:NAVY}, rectRadius:0.1, line:{color:NAVY} });
  s.addText("Who this is for, in Virginia", { isTextBox:true, x:1.0, y:4.08, w:11.3, h:0.35,
    fontFace:B, fontSize:14, bold:true, color:AMBER, margin:0 });
  s.addText("Public universities, K-12 school divisions, county and municipal governments, and small state agencies — all running the same Microsoft 365 estate as a federal agency, all subject to the same expectations, with a fraction of the compliance staff. OSCAL is the format FedRAMP and federal assessors already consume, so the output is immediately useful rather than another bespoke report.",
    { isTextBox:true, x:1.0, y:4.45, w:11.3, h:0.9, fontFace:B, fontSize:13,
      color:"D2DEE8", lineSpacing:19, margin:0 });

  s.addText("Open source under Apache-2.0. Runs on CISA's public data with no tenant access required, so any institution can evaluate it before trusting it with their own.",
    { isTextBox:true, x:0.7, y:5.7, w:11.9, h:0.6, fontFace:B, fontSize:13.5,
      bold:true, color:NAVY2, lineSpacing:20, margin:0 });
  note(s,"The societal case: compliance capability is currently gated on having a GRC team. This removes that gate for exactly the institutions that do not have one.");
}

// ============================ 11. FEASIBILITY ============================
{
  const s = pres.addSlide(); s.background = lightBg();
  kicker(s,"FEASIBILITY");
  title(s,"This is running today, not a prototype sketch");

  const items = [
    ["Real data","CISA's published ScubaGear assessment — a genuine redacted run, CC0 licensed. No synthetic inputs."],
    ["Real validation","NIST oscal-cli in CI. The build fails if any document stops validating."],
    ["Real deployment","Microsoft Foundry project in eastus2, gpt-5-mini, keyless auth. Provisioned and answering."],
    ["Reproducible","Clone, install, generate, validate — four commands, fully offline for the deterministic core."],
    ["Honest about limits","oscal-cli has no mapping command yet, so that document is JSON-Schema validated only. We report cli:n/a rather than implying more."],
  ];
  items.forEach(([h,d],i)=>{
    const y = 1.5 + i*0.98;
    s.addShape(pres.ShapeType.ellipse, { x:0.75, y:y+0.12, w:0.42, h:0.42,
      fill:{color: i===4 ? "FFF1CC" : "E8F6EF"}, line:{color: i===4 ? "FFE2A8":"C3E9D7"} });
    s.addText(i===4 ? "!" : "✓", { isTextBox:true, x:0.75, y:y+0.18, w:0.42, h:0.3,
      fontFace:B, fontSize:13, bold:true, color: i===4 ? "8A5A00" : GREEN,
      align:"center", margin:0 });
    s.addText(h, { isTextBox:true, x:1.35, y:y+0.08, w:2.5, h:0.32, fontFace:B,
      fontSize:13.5, bold:true, color:INK, margin:0 });
    s.addText(d, { isTextBox:true, x:3.9, y:y+0.05, w:8.7, h:0.75, fontFace:B,
      fontSize:12.5, color:GREY, lineSpacing:18, margin:0 });
  });

  s.addText("Next: an Azure Container Apps deployment, Azure AI Search over baseline guidance, and the remaining M365 products.",
    { isTextBox:true, x:0.7, y:6.5, w:11.9, h:0.4, fontFace:B, fontSize:12.5,
      italic:true, color:GREY, margin:0 });
  note(s,"Feasibility is demonstrated rather than argued. Everything on this slide can be checked from the repository in a few minutes.");
}

// ============================ 12. CLOSE ============================
{
  const s = pres.addSlide(); s.background = darkBg();
  s.addShape(pres.ShapeType.ellipse, { x:-1.8, y:4.6, w:5.0, h:5.0, fill:{color:NAVY2} });
  s.addShape(pres.ShapeType.ellipse, { x:11.4, y:-1.2, w:3.6, h:3.6, fill:{color:NAVY2} });

  s.addText("CISA built the scanner.\nWe built everything after it.", { isTextBox:true,
    x:0.9, y:1.45, w:11.2, h:1.5, fontFace:H, fontSize:38, bold:true, color:WHITE,
    lineSpacing:46, margin:0 });

  s.addText("A complete, validated OSCAL chain for Microsoft 365 — with mappings provably faithful to CISA's own crosswalk, drift that survives baseline version changes, and an AI layer that cannot invent a compliance fact.",
    { isTextBox:true, x:0.9, y:3.1, w:10.4, h:0.9, fontFace:B, fontSize:15,
      color:"C6D4E0", lineSpacing:23, margin:0 });

  const stats = [["8","OSCAL documents\nNIST-validated"],["89/92","mappings deterministic\nno AI guessing"],
                 ["26","false findings\neliminated"],["100%","evaluation\naccuracy"]];
  stats.forEach(([v,l],i)=>{
    const x = 0.9 + i*2.95;
    s.addText(v, { isTextBox:true, x, y:4.3, w:2.7, h:0.65, fontFace:B, fontSize:34,
      bold:true, color:AMBER, margin:0 });
    s.addText(l, { isTextBox:true, x, y:4.95, w:2.7, h:0.6, fontFace:B, fontSize:11.5,
      color:"9FB3C8", lineSpacing:15, margin:0 });
  });

  s.addText("github.com/saleha-muzammil/microsoft-sec", { isTextBox:true, x:0.9, y:5.95,
    w:11.2, h:0.4, fontFace:"Courier New", fontSize:14, bold:true, color:CYAN, margin:0 });
  s.addText("Apache-2.0  ·  Built on Microsoft Foundry  ·  Virginia Tech & University of Virginia",
    { isTextBox:true, x:0.9, y:6.45, w:11.2, h:0.35, fontFace:B, fontSize:12,
      color:"7E93A6", margin:0 });
  note(s,"Close on the framing that makes the contribution legible: CISA built detection, we built the compliance layer that turns detection into an auditable package.");
}

pres.writeFile({ fileName: "/tmp/deck/presentation.pptx" })
  .then(f => console.log("written:", f));
