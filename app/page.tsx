'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Inter } from 'next/font/google';
import { ScanResult } from '@/lib/types';

const inter = Inter({ subsets: ['latin'] });

export default function Home() {
  const [input, setInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Auto-detect input type based on content
  const detectInputType = (value: string): 'url' | 'code' => {
    return value.includes('http') ? 'url' : 'code';
  };

  const handleScan = async () => {
    if (!input.trim()) return;

    setIsScanning(true);
    setError(null);
    setResult(null);

    try {
      const inputType = detectInputType(input);
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          [inputType]: input.trim()
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Scan failed');
      }

      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsScanning(false);
    }
  };

  const scrollToScanner = () => {
    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className={`min-h-screen bg-[#09090b] text-zinc-50 ${inter.className}`}>
      {/* Nav */}
      <nav className="border-b border-zinc-800">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="text-xl font-medium text-white">
              SkillScan
            </div>
            <button 
              onClick={scrollToScanner}
              className="text-zinc-400 hover:text-white transition-colors text-sm"
            >
              Scan
            </button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="py-32 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, type: "spring", damping: 20 }}
          >
            <p className="text-sm uppercase tracking-widest text-zinc-500 mb-8 font-medium">
              Security for the AI toolchain
            </p>
            <h1 className="text-6xl md:text-8xl font-light mb-8 text-white leading-tight">
              Know what you&apos;re installing.
            </h1>
            <p className="text-xl text-zinc-400 mb-12 max-w-2xl mx-auto">
              Scan skills before they access your system.
            </p>
            
            <motion.button
              whileHover={{ y: -2 }}
              whileTap={{ y: 0 }}
              onClick={scrollToScanner}
              className="bg-accent hover:bg-accent/90 text-black px-8 py-4 rounded-md text-sm font-medium transition-all"
            >
              Scan a skill →
            </motion.button>
          </motion.div>
        </div>
      </section>

      {/* Scanner */}
      <section id="scanner" className="py-32 px-6">
        <div className="max-w-2xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="space-y-6"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="GitHub URL or paste code directly..."
              className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-4 py-6 text-white placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition-colors"
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            />
            
            <button
              onClick={handleScan}
              disabled={isScanning || !input.trim()}
              className="w-full bg-accent hover:bg-accent/90 text-black py-6 rounded-md font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {isScanning ? 'Scanning...' : 'Scan'}
            </button>
          </motion.div>

          {/* Results */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-12 bg-red-950/50 border border-red-900/50 rounded-md p-6"
            >
              <h3 className="font-medium text-red-400 mb-2">Scan failed</h3>
              <p className="text-red-300 text-sm">{error}</p>
            </motion.div>
          )}

          {result && <ScanResults result={result} />}
        </div>
      </section>

      {/* How it works */}
      <section className="py-32 px-6 bg-zinc-950/50">
        <div className="max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-light mb-4 text-white">How it works</h2>
          </motion.div>
          
          <div className="grid md:grid-cols-3 gap-12 text-left">
            {[
              {
                number: '1',
                title: 'Paste a GitHub URL or skill code',
                description: 'We automatically detect the format and fetch the code for analysis.'
              },
              {
                number: '2',
                title: 'We analyze 12 security vectors',
                description: 'Static analysis identifies common attack patterns and vulnerabilities.'
              },
              {
                number: '3',
                title: 'Get a detailed report in seconds',
                description: 'Review findings with clear severity ratings and remediation advice.'
              }
            ].map((item, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.2 }}
              >
                <div className="text-2xl font-light text-accent mb-4">{item.number}</div>
                <h3 className="text-xl font-medium mb-3 text-white">{item.title}</h3>
                <p className="text-zinc-400 leading-relaxed">{item.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* What we check */}
      <section className="py-32 px-6">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-light mb-4 text-white">What we check</h2>
          </motion.div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { title: 'API token theft', description: 'Unauthorized access to API credentials' },
              { title: 'Shell command execution', description: 'Dangerous system command injection' },
              { title: 'File system abuse', description: 'Unauthorized file access or modification' },
              { title: 'Data exfiltration', description: 'Suspicious network requests and webhooks' },
              { title: 'Code injection', description: 'Dynamic code execution vulnerabilities' },
              { title: 'Hardcoded secrets', description: 'Exposed credentials in source code' },
              { title: 'Prompt injection', description: 'Malicious prompt manipulation attempts' },
              { title: 'Obfuscated code', description: 'Deliberately hidden or encoded logic' },
              { title: 'Excessive permissions', description: 'Unnecessary system access requests' },
            ].map((check, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="bg-zinc-900/50 border border-zinc-800 rounded-md p-6 hover:border-zinc-700 transition-colors group"
              >
                <h3 className="font-medium text-white mb-2 group-hover:text-accent transition-colors">
                  {check.title}
                </h3>
                <p className="text-zinc-400 text-sm leading-relaxed">{check.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800 py-8 px-6">
        <div className="max-w-7xl mx-auto">
          <p className="text-center text-zinc-500 text-sm">
            Built by ninetynine.digital
          </p>
        </div>
      </footer>
    </div>
  );
}

function ScanResults({ result }: { result: ScanResult }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useState(() => {
    const duration = 1500;
    const steps = 30;
    const increment = result.score / steps;
    let current = 0;

    const timer = setInterval(() => {
      current += increment;
      if (current >= result.score) {
        setAnimatedScore(result.score);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.floor(current));
      }
    }, duration / steps);

    return () => clearInterval(timer);
  });

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getGradeColor = (grade: string) => {
    if (grade === 'A' || grade === 'B') return 'text-green-400';
    if (grade === 'C') return 'text-yellow-400';
    return 'text-red-400';
  };

  const getSeverityDot = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-400';
      case 'high': return 'bg-orange-400';
      case 'medium': return 'bg-yellow-400';
      case 'low': return 'bg-blue-400';
      default: return 'bg-gray-400';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="mt-12 space-y-8"
    >
      {/* Score Display */}
      <div className="bg-zinc-900/50 border border-zinc-800 rounded-md p-8 text-center">
        <div className="flex items-center justify-center space-x-6 mb-6">
          <div className={`text-6xl font-light ${getScoreColor(result.score)}`}>
            {animatedScore}
          </div>
          <div className={`text-3xl font-medium ${getGradeColor(result.grade)}`}>
            {result.grade}
          </div>
        </div>
        
        <p className="text-zinc-400 mb-6">{result.summary}</p>
        
        <div className="flex justify-center space-x-8 text-sm">
          <div>
            <div className="text-white font-medium">{result.scannedFiles}</div>
            <div className="text-zinc-500">Files</div>
          </div>
          <div>
            <div className="text-white font-medium">{result.linesAnalyzed.toLocaleString()}</div>
            <div className="text-zinc-500">Lines</div>
          </div>
        </div>
      </div>

      {/* Findings */}
      {result.findings.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-xl font-medium text-white">
            Findings ({result.findings.length})
          </h3>
          
          {result.findings.map((finding, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
              className="bg-zinc-900/50 border border-zinc-800 rounded-md p-6"
            >
              <div className="flex items-start space-x-3">
                <div className={`w-2 h-2 rounded-full mt-2 ${getSeverityDot(finding.severity)}`} />
                <div className="flex-1">
                  <h4 className="font-medium text-white mb-2">{finding.title}</h4>
                  <p className="text-zinc-400 text-sm mb-4">{finding.description}</p>
                  
                  {finding.snippet && (
                    <div className="bg-black/50 border border-zinc-800 rounded p-3 mb-4">
                      <div className="text-xs text-zinc-500 mb-2">
                        {finding.file}{finding.line && `:${finding.line}`}
                      </div>
                      <code className="text-sm font-mono text-zinc-300">
                        {finding.snippet}
                      </code>
                    </div>
                  )}
                  
                  {finding.remediation && (
                    <p className="text-zinc-400 text-sm">
                      <span className="text-zinc-300">Remediation:</span> {finding.remediation}
                    </p>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </motion.div>
  );
}