// Recovery fixture source tree (deterministic: same bytes and times on every run).
//   node make-fixture-tree.mjs create C:\bbtest\rfx\src    version 1
//   node make-fixture-tree.mjs mutate C:\bbtest\rfx\src    version 2: edit, add, delete, one rename
// Version 1: unicode names (Cyrillic, Japanese, Greek, Hebrew, emoji, NFC and NFD accents), a path
// over 260 characters, empty folders, read-only, hidden and hidden+read-only files, zero-byte
// files, one 10 MiB file, a few hundred small files, one already-compressed (.jpg) file. Every
// file and folder gets a fixed modification time.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const [mode, root] = process.argv.slice(2);
if (!['create', 'mutate'].includes(mode) || !root) throw new Error('usage: create|mutate <root>');
const lp = (p) => (p.length >= 240 && !p.startsWith('\\\\?\\') ? '\\\\?\\' + path.resolve(p) : p);

// xorshift32, seeded per use, so content never depends on call order elsewhere.
function rng(seed) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    return x / 4294967296;
  };
}
function bytes(n, seed) {
  const r = rng(seed), b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(r() * 256);
  return b;
}
const WORDS = 'backup restore archive vault passcode folder file version encrypted schedule report invoice spec draft meeting quarterly alpha bravo charlie delta echo window glass order customer delivery'.split(' ');
function text(n, seed) {
  const r = rng(seed); let s = '';
  while (s.length < n) s += WORDS[Math.floor(r() * WORDS.length)] + (r() < 0.1 ? '\r\n' : ' ');
  return s.slice(0, n);
}
const T1 = Date.UTC(2026, 0, 10, 9, 0, 0); // version 1 times
const T2 = Date.UTC(2026, 1, 10, 9, 0, 0); // version 2 times
let seq = 0;
function write(rel, data, t) {
  const p = path.join(root, rel);
  fs.mkdirSync(lp(path.dirname(p)), { recursive: true });
  fs.writeFileSync(lp(p), data);
  const when = new Date(t + (seq++) * 61_000);
  fs.utimesSync(lp(p), when, when);
}
function dir(rel) { fs.mkdirSync(lp(path.join(root, rel)), { recursive: true }); }
function attrib(flags, rel) { execFileSync('attrib', [...flags, path.join(root, rel)]); }
// Folder times last, deepest first, so writing files does not move them afterwards.
function stampFolders(t) {
  const all = [];
  (function walk(d) {
    for (const e of fs.readdirSync(lp(d), { withFileTypes: true })) if (e.isDirectory()) { const p = path.join(d, e.name); all.push(p); walk(p); }
  })(root);
  all.sort((a, b) => b.length - a.length);
  all.forEach((p, i) => { const w = new Date(t + i * 1000); fs.utimesSync(lp(p), w, w); });
}

if (mode === 'create') {
  if (fs.existsSync(root) && fs.readdirSync(root).length) throw new Error(`${root} is not empty`);
  fs.mkdirSync(root, { recursive: true });
  write('README.txt', 'Backup Base recovery fixture. Test data only.\r\n', T1);
  // A few hundred small files: 5 projects x 3 folders x 20 files = 300.
  const kinds = [['notes', 'txt'], ['specs', 'csv'], ['data', 'json']];
  let n = 0;
  for (const proj of ['Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo']) {
    for (const [k, ext] of kinds) {
      for (let i = 1; i <= 20; i++) {
        n++;
        const size = 64 + Math.floor(rng(n * 7919)() * 16000);
        write(`Projects/${proj}/${k}/${k}-${String(i).padStart(3, '0')}.${ext}`, ext === 'json' ? JSON.stringify({ n, text: text(size, n) }) : text(size, n), T1);
      }
    }
  }
  // Unicode names (NFC, plus one NFD name).
  write('Unicode/Документы/отчёт за квартал.txt', text(900, 101), T1);
  write('Unicode/日本語/テスト ファイル.txt', text(700, 102), T1);
  write('Unicode/Ελληνικά/αρχείο σημειώσεων.md', text(800, 103), T1);
  write('Unicode/עברית/קובץ בדיקה.txt', text(600, 104), T1);
  write('Unicode/emoji 🎉 party/🎂 cake & 🍰 slice.txt', text(500, 105), T1);
  write('Unicode/café/naïve façade résumé.txt', text(400, 106), T1);
  write('Unicode/' + 'Cafe\u0301 NFD name.txt', 'NFD: e followed by a combining acute accent\r\n', T1);
  write('Unicode/name with [brackets] & (parens) #1 %20.txt', text(300, 107), T1);
  write('Unicode/UPPER CASE.TXT', text(200, 108), T1);
  // A path over 260 characters (absolute), under deep folders with long names.
  let deep = 'Deep';
  for (let i = 1; i <= 7; i++) deep += `/level-${String(i).padStart(2, '0')}-this-folder-name-is-long-on-purpose`;
  write(`${deep}/file-at-the-end-of-a-very-long-path.txt`, 'This file sits on a path longer than 260 characters.\r\n', T1);
  dir(`${deep}/empty-folder-at-depth`);
  // Empty folders.
  dir('Empty Folder');
  dir('Nested/empty/inside/empty');
  // Zero-byte files.
  write('zero-byte.dat', Buffer.alloc(0), T1);
  write('Projects/Alpha/notes/empty-note.txt', '', T1);
  // Attributes.
  write('Attributes/readonly.txt', 'read-only\r\n', T1);
  write('Attributes/hidden.txt', 'hidden\r\n', T1);
  write('Attributes/hidden-and-readonly.txt', 'hidden and read-only\r\n', T1);
  write('Attributes/.dotfile-config', 'key=value\r\n', T1);
  // One 10 MiB file and one already-compressed type.
  write('Media/sample-10MiB.bin', bytes(10 * 1024 * 1024, 4242), T1);
  write('Media/photo.jpg', bytes(180_000, 4343), T1);
  attrib(['+R'], 'Attributes/readonly.txt');
  attrib(['+H'], 'Attributes/hidden.txt');
  attrib(['+H', '+R'], 'Attributes/hidden-and-readonly.txt');
  stampFolders(T1);
  console.log(`created version 1 in ${root}`);
} else {
  // Edit 6 files (one only by attribute), add 11 files and an empty folder, delete 5 files and a
  // folder with 20 files, rename one file.
  const ed = (rel, add) => { const p = path.join(root, rel); fs.appendFileSync(lp(p), add); const w = new Date(T2 + (seq++) * 61_000); fs.utimesSync(lp(p), w, w); };
  ed('README.txt', 'Version 2.\r\n');
  ed('Projects/Bravo/specs/specs-001.csv', '\r\nedited,in,version,2\r\n');
  ed('Projects/Echo/data/data-020.json', '\n');
  ed('Unicode/日本語/テスト ファイル.txt', '\r\n版 2\r\n');
  const bin = path.join(root, 'Media/photo.jpg');
  const b = fs.readFileSync(bin); b.fill(0x5a, 1000, 1100); fs.writeFileSync(bin, b); fs.utimesSync(bin, new Date(T2), new Date(T2));
  attrib(['+H'], 'Projects/Alpha/notes/notes-010.txt'); // attribute-only change
  // Add.
  for (let i = 1; i <= 8; i++) write(`Projects/Foxtrot/new-${String(i).padStart(2, '0')}.txt`, text(2000 + i * 100, 900 + i), T2);
  write('Unicode/Документы/новый файл.txt', text(500, 950), T2);
  write('Unicode/emoji 🎉 party/🆕 added.txt', text(400, 951), T2);
  write('added-zero-byte.dat', Buffer.alloc(0), T2);
  dir('Empty Folder Added In v2');
  // Delete.
  for (const rel of ['Projects/Alpha/notes/notes-001.txt', 'Projects/Bravo/data/data-005.json', 'Projects/Charlie/specs/specs-010.csv', 'Unicode/UPPER CASE.TXT', 'zero-byte.dat']) fs.rmSync(lp(path.join(root, rel)));
  fs.rmSync(lp(path.join(root, 'Projects/Delta/data')), { recursive: true });
  // Rename (content and time kept).
  fs.renameSync(path.join(root, 'Projects/Echo/notes/notes-005.txt'), path.join(root, 'Projects/Echo/notes/notes-005 renamed.txt'));
  stampFolders(T2);
  console.log(`mutated to version 2 in ${root}`);
}
