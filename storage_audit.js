#!/usr/bin/env node
/**
 * storage_audit.js - Command-Line Storage Audit Utility
 * 
 * Standar Spesifikasi:
 * - STG-01: Recursive Scan (SHA-256, ukuran byte, metadata)
 * - STG-02: Duplicate Detection (Grup hash identik)
 * - STG-03: Giant File Flagging (Ambang batas >= 2 MB / 2.048 KB)
 * - STG-04: Terminal Report (Ringkasan metrik & estimasi hemat)
 * - STG-05: Safe Cleanup Confirmation (Prompt interaktif Y/N, hapus salinan & .tmp)
 * - STG-06: Zero-Dependency Portability (Hanya modul bawaan: fs, path, crypto, readline)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Konfigurasi Ambang Batas
const GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024; // 2 MB = 2.048 KB = 2.097.152 bytes

// Format ukuran byte ke representasi yang mudah dibaca (KB / MB)
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const kb = bytes / 1024;
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) {
    return `${mb.toFixed(2)} MB (${Math.round(kb).toLocaleString('id-ID')} KB)`;
  }
  return `${kb.toFixed(2)} KB (${bytes.toLocaleString('id-ID')} bytes)`;
}

function formatSizeOnly(bytes) {
  const mb = bytes / (1024 * 1024);
  const kb = bytes / 1024;
  if (mb >= 1) {
    return `${mb.toFixed(2)} MB`;
  }
  return `${kb.toFixed(2)} KB`;
}

// Menghitung hash SHA-256 secara streaming (aman untuk file besar)
function getFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

// Penilaian file asli vs duplikat: File asli mendapat skor penalti lebih rendah
function scoreOriginalCandidate(fileName) {
  const lower = fileName.toLowerCase();
  let penalty = 0;
  if (lower.includes('copy')) penalty += 100;
  if (lower.includes('salinan')) penalty += 100;
  if (lower.includes('backup')) penalty += 80;
  if (lower.includes('edit')) penalty += 50;
  if (lower.includes('_v2') || lower.includes('_v3')) penalty += 40;
  if (/\(\d+\)/.test(lower)) penalty += 70;
  return penalty * 1000 + fileName.length;
}

// STG-01: Memindai direktori secara rekursif
async function scanDirectory(dirPath, scriptFilesToIgnore = new Set()) {
  const fileEntries = [];

  async function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      console.error(`[Akses Ditolak/Gagal] Tidak dapat membaca direktori: ${currentDir} (${err.message})`);
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        const resolvedPath = path.resolve(fullPath);
        // Jangan scan skrip audit itu sendiri
        if (scriptFilesToIgnore.has(resolvedPath)) {
          continue;
        }

        try {
          const stats = fs.statSync(fullPath);
          const sha256 = await getFileSha256(fullPath);
          fileEntries.push({
            name: entry.name,
            fullPath: resolvedPath,
            relativePath: path.relative(process.cwd(), fullPath),
            size: stats.size,
            sha256: sha256,
            isTmp: entry.name.toLowerCase().endsWith('.tmp') || entry.name.toLowerCase().endsWith('.temp')
          });
        } catch (err) {
          console.error(`[Peringatan] Gagal memproses file: ${entry.name} (${err.message})`);
        }
      }
    }
  }

  await walk(dirPath);
  return fileEntries;
}

// STG-02: Mengelompokkan duplikat berdasarkan hash SHA-256
function findDuplicateGroups(files) {
  const hashGroups = new Map();

  for (const file of files) {
    if (!hashGroups.has(file.sha256)) {
      hashGroups.set(file.sha256, []);
    }
    hashGroups.get(file.sha256).push(file);
  }

  const duplicates = [];
  for (const [hash, group] of hashGroups.entries()) {
    if (group.length > 1) {
      // Urutkan kandidat sehingga file asli berada di indeks 0
      group.sort((a, b) => scoreOriginalCandidate(a.name) - scoreOriginalCandidate(b.name));
      duplicates.push({
        hash,
        sizePerFile: group[0].size,
        original: group[0],
        copies: group.slice(1),
        allFiles: group
      });
    }
  }

  return duplicates;
}

// STG-03: Menandai file raksasa (>= 2 MB / 2.048 KB)
function findGiantFiles(files) {
  return files
    .filter(file => file.size >= GIANT_FILE_THRESHOLD_BYTES)
    .sort((a, b) => b.size - a.size);
}

// Menemukan file temporary (.tmp / .temp)
function findTmpFiles(files) {
  return files.filter(file => file.isTmp);
}

// STG-04: Menampilkan laporan ringkas di terminal
function printReport(targetDir, files, giantFiles, duplicateGroups, tmpFiles) {
  const totalFiles = files.length;
  const totalSizeBytes = files.reduce((acc, f) => acc + f.size, 0);

  // Estimasi hemat ruang: (jumlah salinan * ukuran) + ukuran file tmp (yang bukan salinan)
  const dupSavedBytes = duplicateGroups.reduce((acc, g) => acc + (g.sizePerFile * g.copies.length), 0);
  const copyPaths = new Set();
  duplicateGroups.forEach(g => g.copies.forEach(c => copyPaths.add(c.fullPath)));
  
  const uniqueTmpFiles = tmpFiles.filter(t => !copyPaths.has(t.fullPath));
  const tmpSavedBytes = uniqueTmpFiles.reduce((acc, t) => acc + t.size, 0);
  const totalSavedBytes = dupSavedBytes + tmpSavedBytes;

  console.log('\n================================================================================');
  console.log('            LAPORAN AUDIT PENYIMPANAN SISTEM - STORAGE AUDIT CLI                ');
  console.log('================================================================================');
  console.log(` Direktori Target : ${targetDir}`);
  console.log(` Total File       : ${totalFiles} file`);
  console.log(` Total Ukuran     : ${formatBytes(totalSizeBytes)}`);
  console.log(` File Raksasa     : ${giantFiles.length} file (>= 2 MB / 2.048 KB)`);
  console.log(` Kelompok Duplikat: ${duplicateGroups.length} kelompok (${duplicateGroups.reduce((acc, g) => acc + g.copies.length, 0)} salinan berlebih)`);
  console.log(` File Sampah .tmp : ${tmpFiles.length} file`);
  console.log(` Estimasi Hemat   : ${formatBytes(totalSavedBytes)}`);
  console.log('================================================================================');

  // STG-03: Daftar File Raksasa
  console.log('\n[ STG-03: DAFTAR FILE RAKSASA (Ambang Batas >= 2 MB / 2.048 KB) ]');
  console.log('--------------------------------------------------------------------------------');
  if (giantFiles.length === 0) {
    console.log(' (Tidak ditemukan file yang melebihi ukuran 2 MB)');
  } else {
    giantFiles.forEach((file, idx) => {
      const num = String(idx + 1).padStart(2, ' ');
      console.log(` ${num}. [${formatSizeOnly(file.size).padStart(8, ' ')}] ${file.name}`);
      console.log(`     Path: ${file.relativePath || file.fullPath} (${file.size.toLocaleString('id-ID')} bytes)`);
    });
  }

  // STG-02: Daftar Kelompok Duplikat
  console.log('\n[ STG-02: DAFTAR KELOMPOK DUPLIKAT (Isi SHA-256 Identik) ]');
  console.log('--------------------------------------------------------------------------------');
  if (duplicateGroups.length === 0) {
    console.log(' (Tidak ditemukan file duplikat)');
  } else {
    duplicateGroups.forEach((g, idx) => {
      console.log(`\n Kelompok Duplikat #${idx + 1}:`);
      console.log(`   SHA-256 : ${g.hash}`);
      console.log(`   Ukuran  : ${formatBytes(g.sizePerFile)} per file`);
      console.log(`   [ASLI]     -> ${g.original.name} (${g.original.relativePath || g.original.fullPath})`);
      g.copies.forEach(c => {
        console.log(`   [DUPLIKAT] -> ${c.name} (${c.relativePath || c.fullPath})`);
      });
    });
  }

  // Ringkasan Hemat Ruang
  console.log('\n--------------------------------------------------------------------------------');
  console.log('[ STG-04: RINGKASAN REKOMENDASI PENGHEMATAN RUANG ]');
  console.log('--------------------------------------------------------------------------------');
  console.log(` - Salinan Duplikat Dapat Dihapus : ${duplicateGroups.reduce((acc, g) => acc + g.copies.length, 0)} file -> Hemat ${formatBytes(dupSavedBytes)}`);
  console.log(` - File Sampah .tmp Dapat Dihapus : ${tmpFiles.length} file -> Hemat ${formatBytes(tmpSavedBytes)}`);
  console.log(` - TOTAL POTENSI RUANG HEMAT      : ${formatBytes(totalSavedBytes)}`);
  console.log('================================================================================\n');

  return {
    totalSavedBytes,
    duplicateGroups,
    uniqueTmpFiles
  };
}

// STG-05: Safe Cleanup Confirmation
async function promptAndCleanup(duplicateGroups, tmpFiles) {
  const filesToDelete = [];

  // Salinan duplikat (mempertahankan 1 file asli per grup)
  for (const group of duplicateGroups) {
    for (const copy of group.copies) {
      filesToDelete.push({
        path: copy.fullPath,
        name: copy.name,
        size: copy.size,
        reason: `Salinan dari [${group.original.name}]`
      });
    }
  }

  // File .tmp sampah
  for (const tmp of tmpFiles) {
    if (!filesToDelete.some(f => f.path === tmp.fullPath)) {
      filesToDelete.push({
        path: tmp.fullPath,
        name: tmp.name,
        size: tmp.size,
        reason: 'File sementara (.tmp/.temp)'
      });
    }
  }

  if (filesToDelete.length === 0) {
    console.log('Tidak ada file duplikat atau sampah yang perlu dibersihkan.\n');
    return;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const question = (query) => new Promise(resolve => rl.question(query, resolve));

  try {
    const answer = await question(
      `Apakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): `
    );

    const trimmed = answer.trim().toUpperCase();
    if (trimmed === 'Y' || trimmed === 'YA' || trimmed === 'YES') {
      console.log('\n[MEMULAI PEMBERSIHAN AMAN]');
      console.log('--------------------------------------------------------------------------------');
      let deletedCount = 0;
      let freedBytes = 0;

      for (const item of filesToDelete) {
        try {
          if (fs.existsSync(item.path)) {
            fs.unlinkSync(item.path);
            deletedCount++;
            freedBytes += item.size;
            console.log(` [BERHASIL DIHAPUS] ${item.name} (${formatBytes(item.size)})`);
            console.log(`   Alasan: ${item.reason}`);
          }
        } catch (err) {
          console.error(` [GAGAL MENGHAPUS]  ${item.name} (${err.message})`);
        }
      }

      console.log('--------------------------------------------------------------------------------');
      console.log(`Pembersihan Selesai: Berhasil menghapus ${deletedCount} file.`);
      console.log(`Ruang Penyimpanan Berhasil Dihemat: ${formatBytes(freedBytes)}\n`);
    } else {
      console.log('\n[BATAL AMAN] Pembersihan dibatalkan oleh pengguna.');
      console.log('Tidak ada file yang dihapus atau diubah.\n');
    }
  } finally {
    rl.close();
  }
}

// Entry Point CLI
async function main() {
  const args = process.argv.slice(2);

  // Filter flag opsional
  const autoConfirm = args.includes('-y') || args.includes('--yes');
  const positionalArgs = args.filter(a => !a.startsWith('-'));

  let targetDir;

  if (positionalArgs.length > 0) {
    const requestedPath = path.resolve(positionalArgs[0]);
    if (fs.existsSync(requestedPath)) {
      targetDir = requestedPath;
    } else {
      // Jika folder seperti "Bahan Latihan P12" diminta tapi tidak ditemukan sebagai subfolder,
      // periksa apakah cwd yang sedang aktif adalah target yang dimaksud
      console.log(`[INFORMASI] Folder "${positionalArgs[0]}" tidak ditemukan di path saat ini.`);
      console.log(`Menggunakan folder kerja saat ini: ${process.cwd()}`);
      targetDir = process.cwd();
    }
  } else {
    // Cek apakah ada subfolder "Bahan Latihan P12" di direktori kerja saat ini
    const p12Path = path.resolve('Bahan Latihan P12');
    if (fs.existsSync(p12Path) && fs.statSync(p12Path).isDirectory()) {
      targetDir = p12Path;
    } else {
      targetDir = process.cwd();
    }
  }

  // Daftarkan file skrip agar tidak ikut terhitung
  const currentScriptPath = path.resolve(__filename);
  const scriptFilesToIgnore = new Set([
    currentScriptPath,
    path.resolve(path.join(__dirname, 'storage_audit.py'))
  ]);

  console.log('\n================================================================================');
  console.log('                 STORAGE AUDIT UTILITY - NODE.JS NATIVE CLI                     ');
  console.log('================================================================================');
  console.log(`Memulai audit pada direktori: ${targetDir}`);
  console.log('Memindai seluruh file dan menghitung hash SHA-256 (STG-01)... Mohon tunggu...');

  const startTime = Date.now();
  const files = await scanDirectory(targetDir, scriptFilesToIgnore);
  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log(`Pemindaian selesai dalam ${durationSec} detik! Total ${files.length} file terdeteksi.`);

  // STG-02: Deteksi Duplikat
  const duplicateGroups = findDuplicateGroups(files);

  // STG-03: Deteksi File Raksasa (>= 2 MB)
  const giantFiles = findGiantFiles(files);

  // Deteksi File Tmp
  const tmpFiles = findTmpFiles(files);

  // STG-04: Tampilkan Laporan di Terminal
  printReport(targetDir, files, giantFiles, duplicateGroups, tmpFiles);

  // STG-05: Konfirmasi Pembersihan Aman
  if (autoConfirm) {
    // Mode non-interaktif (-y) jika dijalankan secara otomatis
    console.log('[AUTO-CONFIRM] Menjalankan pembersihan otomatis (-y)...');
    // Simulate 'Y'
    // Mengumpulkan file yang dihapus
    const filesToDelete = [];
    duplicateGroups.forEach(g => g.copies.forEach(c => filesToDelete.push(c)));
    tmpFiles.forEach(t => {
      if (!filesToDelete.some(f => f.fullPath === t.fullPath)) filesToDelete.push(t);
    });
    let freed = 0;
    filesToDelete.forEach(item => {
      if (fs.existsSync(item.fullPath)) {
        fs.unlinkSync(item.fullPath);
        freed += item.size;
        console.log(` [BERHASIL DIHAPUS] ${item.name} (${formatBytes(item.size)})`);
      }
    });
    console.log(`Pembersihan selesai! Total dihemat: ${formatBytes(freed)}\n`);
  } else {
    await promptAndCleanup(duplicateGroups, tmpFiles);
  }
}

// Eksekusi program
main().catch(err => {
  console.error('\n[FATAL ERROR]', err);
  process.exit(1);
});
