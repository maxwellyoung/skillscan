'use client';

import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence, useSpring } from 'framer-motion';
import { ScanResult, Finding } from '@/lib/types';
import Link from 'next/link';

// Spring presets — physics-first
const spring = {
  responsive: { type: 'spring' as const, stiffness: 400, damping: 30 },
  gentle: { type: 'spring' as const, stiffness: 100, damping: 20 },
  silk: { type: 'spring' as const, stiffness: 200, damping: 25 },
  bouncy: { type: 'spring' as const, stiffness: 300, damping: 15 },
  heavy: { type: 'spring' as const, stiffness: 80, damping: 20 },
};

const EXAMPLES = [
  { label: 'GitHub repo', value: 'https://github.com/microsoft/vscode' },
  { label: 'Paste code', value: `import subprocess\nos.system("rm -rf /")\nAPI_KEY = "sk-1234567890"` },
];

export default function Home() {
  const [input, setInput] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [focused, setFocused] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const detect = (v: string): 'url' | 'code' =>
    v.includes('http') || v.includes('github.com') || v.includes('clawdhub.com') ? 'url' : 'code';

  const scan = async () => {
    if (!input.trim() || scanning) return;
    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const type = detect(input);
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [type]: input.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed');
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white/90 flex flex-col">
      {/* Nav — barely there */}
      <nav className="px-6 py-5 flex items-center justify-between">
        <span className="text-[15px] font-medium tracking-[-0.01em]">SkillScan</span>
        <div className="flex items-center gap-5 text-[13px] text-white/40">
          <Link href="/pricing" className="hover:text-white/70 transition-colors duration-200">
            Pricing
          </Link>
          <a
            href="https://github.com/maxwellyoung/skillscan"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-white/70 transition-colors duration-200"
          >
            Source
          </a>
        </div>
      </nav>

      {/* Scanner — the whole point */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 pb-24">
        <div className="w-full max-w-[560px]">
          {/* Title — one line, then gone */}
          <motion.h1
            className="font-serif text-[32px] font-light tracking-[-0.02em] text-white mb-10 leading-[1.15]"
            style={{ fontFamily: "'Newsreader', serif" }}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={spring.gentle}
          >
            Know what you&apos;re installing.
          </motion.h1>

          {/* Input */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...spring.gentle, delay: 0.05 }}
          >
            <div className="relative">
              <motion.div
                className="absolute inset-0 rounded-lg pointer-events-none"
                animate={{
                  boxShadow: focused
                    ? '0 0 0 1px rgba(255,255,255,0.15)'
                    : '0 0 0 1px rgba(255,255,255,0.06)',
                }}
                transition={spring.silk}
              />
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onFocus={() => setFocused(true)}
                onBlur={() => setFocused(false)}
                placeholder="Paste a GitHub URL or code..."
                className={`w-full bg-white/[0.03] rounded-lg px-4 py-4 text-[14px] text-white/90 placeholder:text-white/20 resize-none leading-relaxed transition-colors duration-200 ${scanning ? 'scanning' : ''}`}
                rows={input.includes('\n') ? Math.min(input.split('\n').length + 1, 10) : 3}
                onKeyDown={(e) => e.key === 'Enter' && e.metaKey && scan()}
              />
              {input.trim() && (
                <motion.span
                  className="absolute top-3 right-3 text-[11px] text-white/20 font-mono"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={spring.responsive}
                >
                  {detect(input)}
                </motion.span>
              )}
            </div>

            {/* Examples — quiet text links */}
            <div className="flex items-center gap-3 mt-3 text-[12px] text-white/25">
              <span>try:</span>
              {EXAMPLES.map((ex, i) => (
                <button
                  key={i}
                  onClick={() => {
                    setInput(ex.value);
                    textareaRef.current?.focus();
                  }}
                  className="hover:text-white/50 transition-colors duration-200 underline underline-offset-2 decoration-white/10 hover:decoration-white/30"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          </motion.div>

          {/* Scan button */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...spring.gentle, delay: 0.1 }}
            className="mt-5"
          >
            <motion.button
              onClick={scan}
              disabled={scanning || !input.trim()}
              className="w-full py-3.5 rounded-lg text-[14px] font-medium transition-colors duration-200 disabled:opacity-30 disabled:cursor-not-allowed bg-white/[0.08] hover:bg-white/[0.12] text-white/80 hover:text-white"
              whileHover={!scanning && input.trim() ? { y: -1 } : {}}
              whileTap={!scanning && input.trim() ? { scale: 0.985 } : {}}
              transition={spring.responsive}
            >
              {scanning ? (
                <span className="flex items-center justify-center gap-2">
                  <motion.span
                    className="block w-3 h-3 rounded-full border-2 border-white/30 border-t-white/80"
                    animate={{ rotate: 360 }}
                    transition={{ duration: 0.8, repeat: Infinity, ease: 'linear' }}
                  />
                  Scanning
                </span>
              ) : (
                'Scan'
              )}
            </motion.button>
            <p className="text-center text-[11px] text-white/15 mt-2.5">
              {'\u2318'} + Enter
            </p>
          </motion.div>

          {/* Error */}
          <AnimatePresence mode="wait">
            {error && (
              <motion.div
                initial={{ opacity: 0, y: 8, height: 0 }}
                animate={{ opacity: 1, y: 0, height: 'auto' }}
                exit={{ opacity: 0, y: -4, height: 0 }}
                transition={spring.silk}
                className="mt-8 px-4 py-3 rounded-lg border border-red-500/20 bg-red-500/[0.05]"
              >
                <p className="text-[13px] text-red-400/80">{error}</p>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Results */}
          <AnimatePresence mode="wait">
            {result && <Results result={result} />}
          </AnimatePresence>
        </div>
      </main>

      {/* Footer — whisper */}
      <footer className="px-6 py-5 text-[12px] text-white/20">
        <a
          href="https://ninetynine.digital"
          target="_blank"
          rel="noopener noreferrer"
          className="hover:text-white/40 transition-colors duration-200"
        >
          ninetynine.digital
        </a>
      </footer>
    </div>
  );
}

// — Results —

function ScoreDisplay({ score, grade }: { score: number; grade: string }) {
  const springVal = useSpring(0, { stiffness: 60, damping: 20 });
  const [shown, setShown] = useState(0);

  useEffect(() => {
    springVal.set(score);
    return springVal.on('change', (v) => setShown(Math.round(v)));
  }, [score, springVal]);

  const color =
    score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-red-400';

  return (
    <motion.div
      className="relative flex items-baseline gap-4 py-8"
      initial={{ opacity: 0, scale: 0.96 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={spring.heavy}
    >
      {/* Muriel Cooper glow layer */}
      <div className={`score-glow ${color}`}>
        <span className="text-[96px] font-extralight tabular-nums">{shown}</span>
      </div>

      <span className={`text-[96px] font-extralight tabular-nums relative z-10 ${color}`}>
        {shown}
      </span>
      <motion.span
        className={`text-[40px] font-light font-serif relative z-10 ${color}`}
        style={{ fontFamily: "'Newsreader', serif" }}
        initial={{ opacity: 0, x: -8 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ ...spring.silk, delay: 0.3 }}
      >
        {grade}
      </motion.span>
    </motion.div>
  );
}

function Results({ result }: { result: ScanResult }) {
  const findingsByCategory = result.findings.reduce((acc, f) => {
    const cat = f.category || 'General';
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(f);
    return acc;
  }, {} as Record<string, Finding[]>);

  const [expanded, setExpanded] = useState<Set<string>>(
    new Set(Object.keys(findingsByCategory))
  );

  const toggle = (cat: string) => {
    const next = new Set(expanded);
    if (next.has(cat)) { next.delete(cat); } else { next.add(cat); }
    setExpanded(next);
  };

  const severityDot = (s: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-400',
      high: 'bg-orange-400',
      medium: 'bg-amber-400',
      low: 'bg-blue-400',
    };
    return colors[s] || 'bg-white/30';
  };

  return (
    <motion.div
      className="mt-10 space-y-1"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ ...spring.gentle, delay: 0.1 }}
    >
      <ScoreDisplay score={result.score} grade={result.grade} />

      {/* Summary */}
      <motion.p
        className="text-[14px] text-white/50 leading-relaxed pb-6"
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ ...spring.gentle, delay: 0.2 }}
      >
        {result.summary}
      </motion.p>

      {/* Stats */}
      <motion.div
        className="flex gap-8 text-[12px] text-white/30 pb-8 border-b border-white/5"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <span>{result.scannedFiles} files</span>
        <span>{result.linesAnalyzed.toLocaleString()} lines</span>
        <span>{result.findings.length} findings</span>
      </motion.div>

      {/* Findings */}
      {Object.entries(findingsByCategory).map(([category, findings], i) => (
        <motion.div
          key={category}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ ...spring.silk, delay: 0.3 + i * 0.05 }}
        >
          <button
            onClick={() => toggle(category)}
            className="w-full flex items-center justify-between py-3.5 text-left group"
          >
            <div className="flex items-center gap-3">
              <span className="text-[14px] text-white/70 group-hover:text-white/90 transition-colors duration-200">
                {category}
              </span>
              <span className="text-[11px] text-white/20 tabular-nums">
                {findings.length}
              </span>
            </div>
            <motion.span
              className="text-[11px] text-white/20"
              animate={{ rotate: expanded.has(category) ? 90 : 0 }}
              transition={spring.responsive}
            >
              &rsaquo;
            </motion.span>
          </button>

          <AnimatePresence>
            {expanded.has(category) && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                {findings.map((finding, j) => (
                  <motion.div
                    key={j}
                    className="pl-4 pb-5 mb-1 border-l border-white/5"
                    initial={{ opacity: 0, x: -4 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ ...spring.silk, delay: j * 0.03 }}
                  >
                    <div className="flex items-start gap-2.5">
                      <span
                        className={`mt-[7px] w-1.5 h-1.5 rounded-full shrink-0 ${severityDot(finding.severity)}`}
                      />
                      <div className="space-y-2 min-w-0">
                        <div>
                          <p className="text-[13px] text-white/80 leading-snug">
                            {finding.title}
                          </p>
                          <p className="text-[12px] text-white/35 leading-relaxed mt-0.5">
                            {finding.description}
                          </p>
                        </div>

                        {finding.snippet && (
                          <div className="code-block">
                            <div className="text-[11px] text-white/20 mb-1.5 font-sans">
                              {finding.file}
                              {finding.line && `:${finding.line}`}
                            </div>
                            <code className="text-[12px] text-white/60">
                              {finding.snippet.split('\n').map((line, k) => (
                                <div key={k}>
                                  <span className="ln">{k + 1}</span>
                                  {line}
                                </div>
                              ))}
                            </code>
                          </div>
                        )}

                        {finding.remediation && (
                          <p className="text-[12px] text-white/30 leading-relaxed pl-3 border-l border-white/8">
                            {finding.remediation}
                          </p>
                        )}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </motion.div>
            )}
          </AnimatePresence>

          <div className="border-b border-white/[0.03]" />
        </motion.div>
      ))}
    </motion.div>
  );
}
