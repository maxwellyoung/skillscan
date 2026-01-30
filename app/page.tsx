'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Inter } from 'next/font/google';
import { ScanResult, Finding } from '@/lib/types';
import { 
  AlertTriangle, 
  AlertCircle, 
  Info, 
  ChevronRight,
  Shield,
  Zap,
  FileText,
  Database,
  Code,
  Key,
  Terminal,
  Eye,
  Lock,
  Copy,
  CheckCircle,
  Loader2
} from 'lucide-react';

const inter = Inter({ subsets: ['latin'] });

// Example scans for easy testing
const EXAMPLE_SCANS = [
  {
    label: 'GitHub Repository',
    url: 'https://github.com/microsoft/vscode',
    type: 'Clean, well-maintained repo'
  },
  {
    label: 'ClawdHub Skill',
    url: 'https://clawdhub.com/skills/example-skill',
    type: 'Sample skill analysis'
  },
  {
    label: 'Suspicious Code',
    code: `import subprocess
import os

# Dangerous: Execute arbitrary shell commands
def execute_command(cmd):
    subprocess.run(cmd, shell=True)

# Hardcoded API key (security issue)
API_KEY = "sk-1234567890abcdef"

# File system access
os.system("rm -rf /")`,
    type: 'Contains security issues'
  }
];

export default function Home() {
  const [input, setInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Auto-detect input type based on content
  const detectInputType = (value: string): 'url' | 'code' => {
    return value.includes('http') || value.includes('github.com') || value.includes('clawdhub.com') ? 'url' : 'code';
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

  const fillExample = (example: typeof EXAMPLE_SCANS[0]) => {
    if (example.url) {
      setInput(example.url);
    } else if (example.code) {
      setInput(example.code);
    }
  };

  const scrollToScanner = () => {
    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className={`min-h-screen bg-background text-foreground ${inter.className}`}>
      {/* Nav */}
      <nav className="border-b border-muted/20 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <motion.div 
              className="text-xl font-medium text-white font-serif"
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 400, damping: 17 }}
            >
              SkillScan
            </motion.div>
            <motion.button 
              onClick={scrollToScanner}
              className="text-muted hover:text-white transition-colors text-sm spring-bounce"
              whileHover={{ y: -1 }}
              whileTap={{ y: 0 }}
            >
              Scan
            </motion.button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="py-32 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ 
              duration: 0.8, 
              type: "spring", 
              stiffness: 100, 
              damping: 20 
            }}
          >
            <motion.p 
              className="text-sm uppercase tracking-widest text-muted mb-8 font-medium"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.2 }}
            >
              Security for the AI toolchain
            </motion.p>
            <motion.h1 
              className="text-6xl md:text-8xl font-light mb-8 text-white leading-tight font-serif editorial-spacing"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, type: "spring", stiffness: 100 }}
            >
              Know what you&apos;re installing.
            </motion.h1>
            <motion.p 
              className="text-xl text-muted mb-12 max-w-2xl mx-auto editorial-spacing"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              Scan skills before they access your system.
            </motion.p>
            
            <motion.button
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              whileHover={{ y: -3, scale: 1.02 }}
              whileTap={{ y: 0, scale: 0.98 }}
              onClick={scrollToScanner}
              className="bg-accent hover:bg-accent/90 text-white px-8 py-4 rounded-md text-sm font-medium transition-all shadow-lg hover:shadow-xl"
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
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="space-y-6"
          >
            {/* Example buttons */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-8">
              {EXAMPLE_SCANS.map((example, index) => (
                <motion.button
                  key={index}
                  onClick={() => fillExample(example)}
                  className="p-4 bg-muted/10 hover:bg-muted/20 border border-muted/20 rounded-lg text-left transition-all group"
                  whileHover={{ y: -2, scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 + index * 0.1 }}
                >
                  <div className="text-sm font-medium text-white mb-1">{example.label}</div>
                  <div className="text-xs text-muted">{example.type}</div>
                </motion.button>
              ))}
            </div>

            <div className="relative">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="GitHub URL, ClawdHub skill URL, or paste code directly..."
                className={`w-full bg-muted/10 border border-muted/30 rounded-lg px-4 py-6 text-white placeholder-muted focus:outline-none focus:border-accent/50 transition-all resize-none ${isScanning ? 'scanning-line' : ''}`}
                rows={input.includes('\n') ? Math.min(input.split('\n').length + 2, 12) : 3}
                onKeyDown={(e) => e.key === 'Enter' && e.metaKey && handleScan()}
              />
              {detectInputType(input) === 'url' && (
                <div className="absolute top-3 right-3 text-xs text-muted bg-muted/20 px-2 py-1 rounded">
                  URL
                </div>
              )}
              {detectInputType(input) === 'code' && input.trim() && (
                <div className="absolute top-3 right-3 text-xs text-muted bg-muted/20 px-2 py-1 rounded">
                  Code
                </div>
              )}
            </div>
            
            <motion.button
              onClick={handleScan}
              disabled={isScanning || !input.trim()}
              className="w-full bg-accent hover:bg-accent/90 text-white py-6 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2"
              whileHover={!isScanning && !input.trim() ? {} : { y: -2 }}
              whileTap={{ scale: 0.98 }}
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <span>Scan Security</span>
              )}
            </motion.button>

            <div className="text-xs text-muted text-center">
              Tip: ⌘ + Enter to scan quickly
            </div>
          </motion.div>

          {/* Results */}
          <AnimatePresence mode="wait">
            {error && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="mt-12 bg-red-950/20 border border-red-900/30 rounded-lg p-6"
              >
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <h3 className="font-medium text-red-400">Scan failed</h3>
                </div>
                <p className="text-red-300 text-sm mt-2">{error}</p>
              </motion.div>
            )}

            {result && <ScanResults result={result} />}
          </AnimatePresence>
        </div>
      </section>

      {/* How it works */}
      <section className="py-32 px-6 bg-muted/5">
        <div className="max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-light mb-4 text-white font-serif">How it works</h2>
            <p className="text-muted editorial-spacing">Simple, fast, and thorough security analysis</p>
          </motion.div>
          
          <div className="grid md:grid-cols-3 gap-12 text-left">
            {[
              {
                number: '1',
                title: 'Paste a GitHub URL or skill code',
                description: 'We automatically detect the format and fetch the code for analysis.',
                icon: FileText
              },
              {
                number: '2', 
                title: 'We analyze 12 security vectors',
                description: 'Static analysis identifies common attack patterns and vulnerabilities.',
                icon: Shield
              },
              {
                number: '3',
                title: 'Get a detailed report in seconds',
                description: 'Review findings with clear severity ratings and remediation advice.',
                icon: CheckCircle
              }
            ].map((item, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: index * 0.2 }}
                className="text-center group"
              >
                <div className="w-16 h-16 bg-accent/10 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:bg-accent/20 transition-colors">
                  <item.icon className="w-8 h-8 text-accent" />
                </div>
                <h3 className="text-xl font-medium mb-3 text-white font-serif">{item.title}</h3>
                <p className="text-muted leading-relaxed editorial-spacing">{item.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* What we check */}
      <section className="py-32 px-6">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-light mb-4 text-white font-serif">What we check</h2>
            <p className="text-muted editorial-spacing">Comprehensive security analysis across 12+ vectors</p>
          </motion.div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { title: 'API token theft', description: 'Unauthorized access to API credentials', icon: Key },
              { title: 'Shell command execution', description: 'Dangerous system command injection', icon: Terminal },
              { title: 'File system abuse', description: 'Unauthorized file access or modification', icon: FileText },
              { title: 'Data exfiltration', description: 'Suspicious network requests and webhooks', icon: Database },
              { title: 'Code injection', description: 'Dynamic code execution vulnerabilities', icon: Code },
              { title: 'Hardcoded secrets', description: 'Exposed credentials in source code', icon: Lock },
              { title: 'Prompt injection', description: 'Malicious prompt manipulation attempts', icon: Zap },
              { title: 'Obfuscated code', description: 'Deliberately hidden or encoded logic', icon: Eye },
              { title: 'Excessive permissions', description: 'Unnecessary system access requests', icon: Shield },
            ].map((check, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="bg-muted/10 border border-muted/20 rounded-lg p-6 hover:border-muted/40 transition-colors group"
                whileHover={{ y: -2 }}
              >
                <div className="flex items-start space-x-4">
                  <div className="w-10 h-10 bg-accent/10 rounded-lg flex items-center justify-center group-hover:bg-accent/20 transition-colors">
                    <check.icon className="w-5 h-5 text-accent" />
                  </div>
                  <div>
                    <h3 className="font-medium text-white mb-2 group-hover:text-accent transition-colors font-serif">
                      {check.title}
                    </h3>
                    <p className="text-muted text-sm leading-relaxed editorial-spacing">{check.description}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CLI Section */}
      <section className="py-32 px-6 bg-muted/5">
        <div className="max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-light mb-4 text-white font-serif">Command Line Interface</h2>
            <p className="text-muted editorial-spacing">Integrate security scanning into your development workflow</p>
          </motion.div>

          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="syntax-highlight"
            >
              <div className="flex justify-between items-center mb-4">
                <span className="text-accent text-sm font-medium">Scan via curl</span>
                <motion.button
                  className="text-muted hover:text-white transition-colors"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Copy className="w-4 h-4" />
                </motion.button>
              </div>
              <code className="text-sm">
{`# Scan a GitHub repository
curl -X POST https://skillscan-rouge.vercel.app/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://github.com/user/repo"}'

# Scan code directly  
curl -X POST https://skillscan-rouge.vercel.app/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"code": "your code here"}'`}
              </code>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.1 }}
              className="grid md:grid-cols-2 gap-6 text-sm"
            >
              <div>
                <h4 className="font-medium text-white mb-2 font-serif">Response Format</h4>
                <p className="text-muted editorial-spacing">JSON response with security score, grade, and detailed findings</p>
              </div>
              <div>
                <h4 className="font-medium text-white mb-2 font-serif">Integration</h4>
                <p className="text-muted editorial-spacing">Perfect for CI/CD pipelines, pre-commit hooks, and automated workflows</p>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-muted/20 py-12 px-6">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-center"
          >
            <p className="text-muted text-sm mb-4">
              Built with care by{' '}
              <motion.a 
                href="https://ninetynine.digital" 
                className="text-accent hover:text-accent/80 transition-colors"
                whileHover={{ scale: 1.05 }}
                target="_blank"
                rel="noopener noreferrer"
              >
                ninetynine.digital
              </motion.a>
            </p>
            <div className="flex items-center justify-center space-x-6 text-xs text-muted">
              <span>Secure by design</span>
              <span>•</span>
              <span>Privacy focused</span>
              <span>•</span>
              <span>Open source friendly</span>
            </div>
          </motion.div>
        </div>
      </footer>
    </div>
  );
}

function ScanResults({ result }: { result: ScanResult }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());

  // Animated score counter
  useEffect(() => {
    const duration = 1500;
    const steps = 60;
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
  }, [result.score]);

  // Group findings by category
  const findingsByCategory = result.findings.reduce((acc, finding) => {
    const category = finding.category || 'General';
    if (!acc[category]) acc[category] = [];
    acc[category].push(finding);
    return acc;
  }, {} as Record<string, Finding[]>);

  const toggleCategory = (category: string) => {
    const newCollapsed = new Set(collapsedCategories);
    if (newCollapsed.has(category)) {
      newCollapsed.delete(category);
    } else {
      newCollapsed.add(category);
    }
    setCollapsedCategories(newCollapsed);
  };

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

  const getSeverityInfo = (severity: string) => {
    switch (severity) {
      case 'critical':
        return { color: 'text-red-400', bgColor: 'bg-red-400/20', icon: AlertTriangle };
      case 'high':
        return { color: 'text-orange-400', bgColor: 'bg-orange-400/20', icon: AlertCircle };
      case 'medium':
        return { color: 'text-yellow-400', bgColor: 'bg-yellow-400/20', icon: AlertCircle };
      case 'low':
        return { color: 'text-blue-400', bgColor: 'bg-blue-400/20', icon: Info };
      default:
        return { color: 'text-gray-400', bgColor: 'bg-gray-400/20', icon: Info };
    }
  };

  const formatCode = (snippet: string) => {
    return snippet.split('\n').map((line, index) => (
      <div key={index} className="flex">
        <span className="line-number">{index + 1}</span>
        <span>{line}</span>
      </div>
    ));
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="mt-12 space-y-8"
    >
      {/* Dramatic Score Display */}
      <motion.div
        className="bg-muted/10 border border-muted/20 rounded-lg p-8 text-center"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.8, type: "spring", stiffness: 100 }}
      >
        <div className="flex items-center justify-center space-x-8 mb-6">
          <motion.div 
            className={`text-8xl font-light ${getScoreColor(result.score)}`}
            initial={{ scale: 0.5 }}
            animate={{ scale: 1 }}
            transition={{ duration: 1, type: "spring", stiffness: 100 }}
          >
            {animatedScore}
          </motion.div>
          <motion.div 
            className={`text-5xl font-medium ${getGradeColor(result.grade)} font-serif`}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.5 }}
          >
            {result.grade}
          </motion.div>
        </div>
        
        <motion.p 
          className="text-muted mb-8 text-lg editorial-spacing"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
        >
          {result.summary}
        </motion.p>
        
        <motion.div 
          className="flex justify-center space-x-12 text-sm"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.2 }}
        >
          <div>
            <div className="text-white font-medium text-2xl">{result.scannedFiles}</div>
            <div className="text-muted">Files</div>
          </div>
          <div>
            <div className="text-white font-medium text-2xl">{result.linesAnalyzed.toLocaleString()}</div>
            <div className="text-muted">Lines</div>
          </div>
        </motion.div>
      </motion.div>

      {/* Collapsible Findings by Category */}
      {Object.keys(findingsByCategory).length > 0 && (
        <div className="space-y-4">
          <motion.h3 
            className="text-xl font-medium text-white font-serif"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
          >
            Security Findings ({result.findings.length})
          </motion.h3>
          
          {Object.entries(findingsByCategory).map(([category, findings], categoryIndex) => (
            <motion.div
              key={category}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: categoryIndex * 0.1 }}
              className="bg-muted/10 border border-muted/20 rounded-lg overflow-hidden"
            >
              <motion.button
                onClick={() => toggleCategory(category)}
                className="w-full p-4 flex items-center justify-between hover:bg-muted/10 transition-colors"
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.99 }}
              >
                <div className="flex items-center space-x-3">
                  <span className="text-white font-medium font-serif">{category}</span>
                  <span className="text-xs text-muted bg-muted/20 px-2 py-1 rounded-full">
                    {findings.length} finding{findings.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <motion.div
                  animate={{ rotate: collapsedCategories.has(category) ? 0 : 90 }}
                  transition={{ duration: 0.2 }}
                >
                  <ChevronRight className="w-5 h-5 text-muted" />
                </motion.div>
              </motion.button>
              
              <AnimatePresence>
                {!collapsedCategories.has(category) && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3 }}
                    className="border-t border-muted/20"
                  >
                    {findings.map((finding, findingIndex) => {
                      const severityInfo = getSeverityInfo(finding.severity);
                      const SeverityIcon = severityInfo.icon;
                      
                      return (
                        <motion.div
                          key={findingIndex}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ duration: 0.3, delay: findingIndex * 0.1 }}
                          className="p-6 border-b border-muted/10 last:border-b-0"
                        >
                          <div className="flex items-start space-x-4">
                            <div className={`${severityInfo.bgColor} p-2 rounded-lg`}>
                              <SeverityIcon className={`w-4 h-4 ${severityInfo.color}`} />
                            </div>
                            <div className="flex-1 space-y-3">
                              <div>
                                <h4 className="font-medium text-white mb-1 font-serif">{finding.title}</h4>
                                <p className="text-muted text-sm editorial-spacing">{finding.description}</p>
                              </div>
                              
                              {finding.snippet && (
                                <div className="syntax-highlight">
                                  <div className="text-xs text-muted mb-2">
                                    <FileText className="w-3 h-3 inline mr-1" />
                                    {finding.file}{finding.line && `:${finding.line}`}
                                  </div>
                                  <code className="text-sm">
                                    {formatCode(finding.snippet)}
                                  </code>
                                </div>
                              )}
                              
                              {finding.remediation && (
                                <div className="bg-accent/10 border border-accent/20 rounded-lg p-3">
                                  <div className="text-accent text-sm font-medium mb-1">Recommended Fix</div>
                                  <p className="text-white text-sm editorial-spacing">{finding.remediation}</p>
                                </div>
                              )}
                            </div>
                          </div>
                        </motion.div>
                      );
                    })}
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      )}
    </motion.div>
  );
}