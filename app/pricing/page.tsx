'use client';

import { motion } from 'framer-motion';
import { Inter } from 'next/font/google';
import { Check, Zap, Shield, Building2, ArrowLeft } from 'lucide-react';
import Link from 'next/link';

const inter = Inter({ subsets: ['latin'] });

const tiers = [
  {
    name: 'Free',
    price: '$0',
    period: 'forever',
    description: 'For individual developers scanning open-source skills.',
    features: [
      'Unlimited web scans',
      '13 security checks',
      'GitHub & ClawdHub support',
      'Instant results',
      'API access (100 req/day)',
    ],
    cta: 'Start Scanning',
    ctaLink: '/#scanner',
    highlighted: false,
    icon: Shield,
  },
  {
    name: 'Pro',
    price: '$9',
    period: '/month',
    description: 'For power users and teams who need deeper scanning.',
    features: [
      'Everything in Free',
      'Private repo scanning',
      'API access (10,000 req/day)',
      'Webhook notifications',
      'Priority scanning queue',
      'CI/CD integration guide',
      'Scan history & reports',
    ],
    cta: 'Coming Soon',
    ctaLink: '#',
    highlighted: true,
    icon: Zap,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    description: 'For organizations securing their AI toolchain at scale.',
    features: [
      'Everything in Pro',
      'Unlimited API access',
      'Custom scanning rules',
      'SBOM generation',
      'SSO & team management',
      'SLA & priority support',
      'On-prem deployment option',
    ],
    cta: 'Contact Us',
    ctaLink: 'mailto:maxwell@ninetynine.digital?subject=SkillScan%20Enterprise',
    highlighted: false,
    icon: Building2,
  },
];

export default function PricingPage() {
  return (
    <div className={`min-h-screen bg-background text-foreground ${inter.className}`}>
      {/* Nav */}
      <nav className="border-b border-white/5 backdrop-blur-sm sticky top-0 z-50 bg-black/80">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link href="/">
              <motion.div
                className="text-xl font-medium text-white font-serif"
                whileHover={{ scale: 1.02 }}
                transition={{ type: 'spring', stiffness: 400, damping: 17 }}
              >
                SkillScan
              </motion.div>
            </Link>
            <Link href="/">
              <motion.span
                className="text-muted hover:text-white transition-colors text-sm flex items-center gap-1.5"
                whileHover={{ x: -2 }}
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Back to Scanner
              </motion.span>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-24 pb-16 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <p className="text-sm uppercase tracking-widest text-muted mb-6 font-medium">
              Pricing
            </p>
            <h1 className="text-5xl md:text-7xl font-light mb-6 text-white font-serif">
              Security shouldn&apos;t be a luxury.
            </h1>
            <p className="text-xl text-muted max-w-2xl mx-auto editorial-spacing">
              SkillScan is free for individual developers. Upgrade for private repos,
              higher API limits, and team features.
            </p>
          </motion.div>
        </div>
      </section>

      {/* Pricing Cards */}
      <section className="py-16 px-6">
        <div className="max-w-6xl mx-auto grid md:grid-cols-3 gap-6">
          {tiers.map((tier, index) => (
            <motion.div
              key={tier.name}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.15 }}
              className={`relative rounded-xl p-8 flex flex-col ${
                tier.highlighted
                  ? 'bg-white/[0.03] border-2 border-accent/40 shadow-[0_0_40px_-12px_hsl(355,78%,58%,0.15)]'
                  : 'bg-white/[0.02] border border-white/5'
              }`}
            >
              {tier.highlighted && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                  <span className="bg-accent text-white text-xs font-medium px-3 py-1 rounded-full">
                    Most Popular
                  </span>
                </div>
              )}

              <div className="mb-8">
                <div className="flex items-center gap-3 mb-4">
                  <div
                    className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                      tier.highlighted ? 'bg-accent/20' : 'bg-white/5'
                    }`}
                  >
                    <tier.icon
                      className={`w-5 h-5 ${
                        tier.highlighted ? 'text-accent' : 'text-muted'
                      }`}
                    />
                  </div>
                  <h3 className="text-xl font-medium text-white font-serif">
                    {tier.name}
                  </h3>
                </div>

                <div className="flex items-baseline gap-1 mb-3">
                  <span className="text-4xl font-light text-white">
                    {tier.price}
                  </span>
                  {tier.period && (
                    <span className="text-muted text-sm">{tier.period}</span>
                  )}
                </div>

                <p className="text-muted text-sm editorial-spacing">
                  {tier.description}
                </p>
              </div>

              <ul className="space-y-3 mb-8 flex-1">
                {tier.features.map((feature, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-sm">
                    <Check
                      className={`w-4 h-4 mt-0.5 flex-shrink-0 ${
                        tier.highlighted ? 'text-accent' : 'text-white/40'
                      }`}
                    />
                    <span className="text-white/80">{feature}</span>
                  </li>
                ))}
              </ul>

              <motion.a
                href={tier.ctaLink}
                className={`block text-center py-3.5 rounded-lg text-sm font-medium transition-all ${
                  tier.highlighted
                    ? 'bg-accent hover:bg-accent/90 text-white'
                    : 'bg-white/5 hover:bg-white/10 text-white border border-white/10'
                } ${tier.cta === 'Coming Soon' ? 'opacity-80 cursor-default' : ''}`}
                whileHover={tier.cta !== 'Coming Soon' ? { y: -2 } : {}}
                whileTap={tier.cta !== 'Coming Soon' ? { scale: 0.98 } : {}}
              >
                {tier.cta}
              </motion.a>
            </motion.div>
          ))}
        </div>
      </section>

      {/* FAQ / Bottom CTA */}
      <section className="py-24 px-6">
        <div className="max-w-2xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <h2 className="text-3xl font-light mb-4 text-white font-serif">
              Questions?
            </h2>
            <p className="text-muted mb-8 editorial-spacing">
              SkillScan is built by{' '}
              <a
                href="https://ninetynine.digital"
                className="text-accent hover:text-accent/80 transition-colors"
                target="_blank"
                rel="noopener noreferrer"
              >
                ninetynine.digital
              </a>
              . Reach out at{' '}
              <a
                href="mailto:maxwell@ninetynine.digital"
                className="text-accent hover:text-accent/80 transition-colors"
              >
                maxwell@ninetynine.digital
              </a>
            </p>
            <Link href="/">
              <motion.span
                className="inline-block bg-white/5 hover:bg-white/10 border border-white/10 text-white px-6 py-3 rounded-lg text-sm font-medium transition-all"
                whileHover={{ y: -2 }}
                whileTap={{ scale: 0.98 }}
              >
                ← Back to Scanner
              </motion.span>
            </Link>
          </motion.div>
        </div>
      </section>
    </div>
  );
}
