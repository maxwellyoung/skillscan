'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Search, AlertTriangle, CheckCircle, FileX, Network, Key, Code, Zap, AlertCircle } from 'lucide-react';
import { ScanResult } from '@/lib/types';

export default function Home() {
  const [input, setInput] = useState('');
  const [inputType, setInputType] = useState<'url' | 'code'>('url');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!input.trim()) return;

    setIsScanning(true);
    setError(null);
    setResult(null);

    try {
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
    <div className="min-h-screen bg-dark-bg text-dark-fg">
      {/* Header */}
      <header className="border-b border-muted/20">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center space-x-3">
            <Shield className="text-terminal-green w-8 h-8" />
            <h1 className="text-2xl font-bold gradient-text">SkillScan</h1>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-4">
        <div className="container mx-auto max-w-6xl">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center"
          >
            <h1 className="text-5xl md:text-7xl font-bold mb-6">
              Every skill is{' '}
              <span className="gradient-text">guilty until proven safe</span>
            </h1>
            <p className="text-xl md:text-2xl text-muted mb-8 max-w-3xl mx-auto">
              Don&apos;t read every file yourself. Let us scan ClawdHub skills for malicious code in seconds.
            </p>
            <p className="text-lg text-warning mb-12 max-w-2xl mx-auto font-semibold">
              Inspired by the viral &quot;It Got Worse - Clawdbot&quot; video exposing thousands of compromised instances
            </p>
            
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={scrollToScanner}
              className="bg-terminal-green text-black px-8 py-4 rounded-lg text-lg font-semibold hover:bg-terminal-green/90 transition-colors glow-green"
            >
              Scan a Skill
            </motion.button>
          </motion.div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 px-4 bg-black/20">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-16">How It Works</h2>
          
          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                step: '1',
                title: 'Paste ClawdHub or GitHub URL',
                description: 'Drop in a ClawdHub skill link or GitHub repository - we handle both',
                icon: <Code className="w-8 h-8" />
              },
              {
                step: '2',
                title: 'We scan for 13 attack vectors',
                description: 'Static analysis based on real ClawdHub compromises and supply chain attacks',
                icon: <Search className="w-8 h-8" />
              },
              {
                step: '3',
                title: 'Get instant security verdict',
                description: 'Know if it&apos;s safe to install before it touches your system',
                icon: <Shield className="w-8 h-8" />
              }
            ].map((item, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.2 }}
                className="text-center"
              >
                <div className="bg-terminal-green/10 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                  <div className="text-terminal-green">
                    {item.icon}
                  </div>
                </div>
                <div className="bg-terminal-green/20 text-terminal-green w-8 h-8 rounded-full flex items-center justify-center mx-auto mb-4 text-sm font-bold">
                  {item.step}
                </div>
                <h3 className="text-xl font-semibold mb-3">{item.title}</h3>
                <p className="text-muted">{item.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Why This Exists */}
      <section className="py-20 px-4 bg-warning/5 border-y border-warning/20">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">The ClawdHub Supply Chain Crisis</h2>
          
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-8">
                <h3 className="text-xl font-bold text-red-400 mb-4">What Nick Saraev Exposed:</h3>
                <ul className="space-y-3 text-red-200">
                  <li className="flex items-start space-x-3">
                    <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                    <span>ClawdHub has <strong>NO vetting process</strong> - any skill can be published</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                    <span>Thousands of Clawdbot instances compromised via Shodan scanning</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                    <span>Malicious skills stealing API tokens and sensitive data</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                    <span>Supply chain attacks through skill repositories</span>
                  </li>
                </ul>
              </div>
              
              <blockquote className="text-lg italic text-muted border-l-4 border-terminal-green pl-6">
                &quot;Read every file or feed files to AI to check safety&quot;
                <footer className="text-sm text-muted mt-2">- Nick Saraev&apos;s advice to viewers</footer>
              </blockquote>
            </div>
            
            <div>
              <div className="bg-terminal-green/10 border border-terminal-green/30 rounded-xl p-6">
                <h3 className="text-xl font-bold text-terminal-green mb-4">Our Solution:</h3>
                <ul className="space-y-3 text-green-200">
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="w-5 h-5 text-terminal-green mt-0.5 flex-shrink-0" />
                    <span>Automated security analysis in seconds (not hours)</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="w-5 h-5 text-terminal-green mt-0.5 flex-shrink-0" />
                    <span>Direct ClawdHub URL scanning support</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="w-5 h-5 text-terminal-green mt-0.5 flex-shrink-0" />
                    <span>Detects API token theft attempts</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="w-5 h-5 text-terminal-green mt-0.5 flex-shrink-0" />
                    <span>Identifies webhook data exfiltration</span>
                  </li>
                  <li className="flex items-start space-x-3">
                    <CheckCircle className="w-5 h-5 text-terminal-green mt-0.5 flex-shrink-0" />
                    <span>13+ security checks based on real attack vectors</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
          
          <div className="text-center mt-12">
            <p className="text-xl text-warning font-semibold">
              Don&apos;t be the next victim. Scan before you install.
            </p>
          </div>
        </div>
      </section>

      {/* Risk Categories */}
      <section className="py-20 px-4">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-16">13 Security Checks</h2>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { title: 'API token theft', icon: <Key className="w-6 h-6" />, color: 'text-red-400' },
              { title: 'Webhook data exfiltration', icon: <Network className="w-6 h-6" />, color: 'text-red-400' },
              { title: 'Shell command execution', icon: <Code className="w-6 h-6" />, color: 'text-red-400' },
              { title: 'Prompt injection', icon: <AlertTriangle className="w-6 h-6" />, color: 'text-orange-400' },
              { title: 'Hardcoded credentials', icon: <Key className="w-6 h-6" />, color: 'text-yellow-400' },
              { title: 'File system abuse', icon: <FileX className="w-6 h-6" />, color: 'text-orange-400' },
              { title: 'Dynamic code execution', icon: <Zap className="w-6 h-6" />, color: 'text-red-400' },
              { title: 'Obfuscated malware', icon: <Code className="w-6 h-6" />, color: 'text-orange-400' },
              { title: 'Excessive permissions', icon: <Shield className="w-6 h-6" />, color: 'text-yellow-400' },
            ].map((category, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="bg-muted/10 border border-muted/20 rounded-lg p-4 flex items-center space-x-3"
              >
                <div className={category.color}>
                  {category.icon}
                </div>
                <span className="font-medium">{category.title}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Scanner Interface */}
      <section id="scanner" className="py-20 px-4 bg-black/20">
        <div className="container mx-auto max-w-4xl">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">Security Scanner</h2>
          
          <div className="bg-muted/5 border border-muted/20 rounded-xl p-8">
            <div className="mb-6">
              <div className="flex space-x-4 mb-4">
                <button
                  onClick={() => setInputType('url')}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    inputType === 'url'
                      ? 'bg-terminal-green text-black'
                      : 'bg-muted/20 text-muted hover:bg-muted/30'
                  }`}
                >
                  ClawdHub / GitHub URL
                </button>
                <button
                  onClick={() => setInputType('code')}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    inputType === 'code'
                      ? 'bg-terminal-green text-black'
                      : 'bg-muted/20 text-muted hover:bg-muted/30'
                  }`}
                >
                  Paste Code
                </button>
              </div>
              
              {inputType === 'url' ? (
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="https://claudhub.ai/skills/username/skillname or https://github.com/username/repo"
                  className="w-full bg-black/50 border border-muted/30 rounded-lg px-4 py-3 text-dark-fg placeholder-muted focus:outline-none focus:border-terminal-green"
                />
              ) : (
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Paste your skill code here..."
                  rows={8}
                  className="w-full bg-black/50 border border-muted/30 rounded-lg px-4 py-3 text-dark-fg placeholder-muted focus:outline-none focus:border-terminal-green font-mono text-sm"
                />
              )}
            </div>
            
            <button
              onClick={handleScan}
              disabled={isScanning || !input.trim()}
              className="w-full bg-terminal-green text-black py-4 rounded-lg font-semibold text-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-terminal-green/90 transition-colors"
            >
              {isScanning ? 'Scanning...' : 'Scan for Security Issues'}
            </button>
          </div>

          {/* Results */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-8 bg-red-500/10 border border-red-500/30 rounded-xl p-6"
            >
              <div className="flex items-center space-x-3">
                <AlertCircle className="w-6 h-6 text-red-400" />
                <div>
                  <h3 className="font-semibold text-red-400">Scan Failed</h3>
                  <p className="text-red-300">{error}</p>
                </div>
              </div>
            </motion.div>
          )}

          {result && <ScanResults result={result} />}
        </div>
      </section>

      {/* Social Proof */}
      <section className="py-12 px-4">
        <div className="container mx-auto max-w-6xl">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6 }}
            className="text-center"
          >
            <p className="text-2xl font-bold text-terminal-green">
              <CountUpAnimation target={1247} />+ skills scanned
            </p>
            <p className="text-muted mt-2">Protecting developers from ClawdHub supply chain attacks</p>
          </motion.div>
        </div>
      </section>

      {/* Pricing */}
      <section className="py-20 px-4 bg-black/20">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-16">Pricing</h2>
          
          <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
            <div className="bg-muted/5 border border-muted/20 rounded-xl p-8">
              <h3 className="text-2xl font-bold mb-4">Free</h3>
              <div className="text-3xl font-bold mb-6">
                $0<span className="text-lg text-muted font-normal">/month</span>
              </div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>5 scans per day</span>
                </li>
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>Basic security analysis</span>
                </li>
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>Public GitHub repos</span>
                </li>
              </ul>
              <button className="w-full bg-muted/20 text-dark-fg py-3 rounded-lg font-semibold hover:bg-muted/30 transition-colors">
                Get Started
              </button>
            </div>
            
            <div className="bg-terminal-green/10 border border-terminal-green/30 rounded-xl p-8 relative">
              <div className="absolute top-4 right-4 bg-terminal-green text-black px-3 py-1 rounded-full text-sm font-semibold">
                Popular
              </div>
              <h3 className="text-2xl font-bold mb-4">Pro</h3>
              <div className="text-3xl font-bold mb-6">
                $9<span className="text-lg text-muted font-normal">/month</span>
              </div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>Unlimited scans</span>
                </li>
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>Advanced security analysis</span>
                </li>
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>Private repository support</span>
                </li>
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>Continuous monitoring</span>
                </li>
                <li className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-terminal-green" />
                  <span>Security badge for verified skills</span>
                </li>
              </ul>
              <button className="w-full bg-terminal-green text-black py-3 rounded-lg font-semibold hover:bg-terminal-green/90 transition-colors glow-green">
                Upgrade to Pro
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-muted/20 py-12 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="text-terminal-green w-6 h-6" />
              <span className="font-bold gradient-text">SkillScan</span>
            </div>
            <p className="text-muted">
              Built for security-conscious developers
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

function CountUpAnimation({ target }: { target: number }) {
  const [count, setCount] = useState(0);

  useState(() => {
    const duration = 2000;
    const steps = 50;
    const increment = target / steps;
    let current = 0;

    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        setCount(target);
        clearInterval(timer);
      } else {
        setCount(Math.floor(current));
      }
    }, duration / steps);

    return () => clearInterval(timer);
  });

  return <span>{count.toLocaleString()}</span>;
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

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-400/10 border-red-400/30';
      case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/30';
      case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
      case 'low': return 'text-blue-400 bg-blue-400/10 border-blue-400/30';
      default: return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="mt-8 space-y-6"
    >
      {/* Score Display */}
      <div className="bg-black/50 border border-muted/30 rounded-xl p-8 text-center">
        <div className="mb-4">
          <div className={`text-6xl font-bold ${getScoreColor(result.score)}`}>
            {animatedScore}
          </div>
          <div className="text-muted">Security Score</div>
        </div>
        
        <div className="flex justify-center items-center space-x-8 mb-6">
          <div>
            <div className={`text-2xl font-bold ${getGradeColor(result.grade)}`}>
              {result.grade}
            </div>
            <div className="text-sm text-muted">Grade</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-dark-fg">
              {result.scannedFiles}
            </div>
            <div className="text-sm text-muted">Files</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-dark-fg">
              {result.linesAnalyzed.toLocaleString()}
            </div>
            <div className="text-sm text-muted">Lines</div>
          </div>
        </div>
        
        <p className="text-muted">{result.summary}</p>
      </div>

      {/* Findings */}
      {result.findings.length > 0 && (
        <div className="bg-black/50 border border-muted/30 rounded-xl p-8">
          <h3 className="text-xl font-semibold mb-6">
            Security Findings ({result.findings.length})
          </h3>
          
          <div className="space-y-4">
            {result.findings.map((finding, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: index * 0.1 }}
                className="border border-muted/20 rounded-lg p-4"
              >
                <div className="flex items-start space-x-4">
                  <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(finding.severity)}`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <div className="flex-1">
                    <h4 className="font-semibold mb-2">{finding.title}</h4>
                    <p className="text-muted mb-3">{finding.description}</p>
                    
                    {finding.snippet && (
                      <div className="bg-black/70 border border-muted/20 rounded p-3 mb-3">
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-sm text-muted">
                            {finding.file}{finding.line && `:${finding.line}`}
                          </span>
                        </div>
                        <code className="text-sm font-mono text-terminal-green">
                          {finding.snippet}
                        </code>
                      </div>
                    )}
                    
                    {finding.remediation && (
                      <div className="bg-blue-500/10 border border-blue-500/30 rounded p-3">
                        <div className="text-sm">
                          <strong className="text-blue-400">Remediation:</strong>{' '}
                          <span className="text-blue-200">{finding.remediation}</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex space-x-4">
        <button className="px-6 py-3 bg-terminal-green text-black rounded-lg font-semibold hover:bg-terminal-green/90 transition-colors">
          Share Report
        </button>
        <button className="px-6 py-3 bg-muted/20 text-dark-fg rounded-lg font-semibold hover:bg-muted/30 transition-colors">
          Request Verification
        </button>
      </div>
    </motion.div>
  );
}