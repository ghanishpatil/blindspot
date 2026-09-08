import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { Icon } from '@/components/Icon';
import { missingFirebaseConfigKeys } from '@/services/firebase';

export default function Login() {
  const navigate = useNavigate();
  const missingKeys = missingFirebaseConfigKeys();
  const isFirebaseConfigured = missingKeys.length === 0;

  const [email, setEmail] = useState('security@blindspot.internal');
  const [password, setPassword] = useState('demo-password');
  const [loading, setLoading] = useState(false);
  const [error] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);

    // Direct navigation to dashboard for demo mode
    setTimeout(() => {
      setLoading(false);
      navigate('/dashboard');
    }, 400);
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#080B0F] px-4 text-slate-100 font-sans">
      <div className="w-full max-w-md space-y-8">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <Link to="/" className="inline-flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-[#7DB7E8]/30 bg-[#11171E] text-[#7DB7E8]">
              <Icon name="shield" size={24} />
            </div>
          </Link>
          <h1 className="font-mono text-2xl font-bold tracking-wider text-slate-100">BLINDSPOT ECDAT</h1>
          <p className="font-mono text-xs uppercase tracking-widest text-[#7DB7E8]">
            Enterprise Cryptographic Discovery
          </p>
          <p className="text-xs text-slate-400">"You cannot migrate cryptography you cannot find."</p>
        </div>

        {/* Login Form Box */}
        <div className="rounded-2xl border border-[#222B35] bg-[#11171E] p-8 shadow-2xl space-y-6">
          {!isFirebaseConfigured ? (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300">
              <span className="font-semibold block">Local Demo Mode Active</span>
              Firebase environment variables unconfigured. Clicking sign-in will log you into the demo workspace directly.
            </div>
          ) : null}

          {error ? (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
              {error}
            </div>
          ) : null}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-xs font-mono font-medium text-slate-300 mb-1">
                Security Engineering Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] px-3.5 py-2.5 text-xs text-slate-200 focus:border-[#7DB7E8] focus:outline-none font-mono"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-xs font-mono font-medium text-slate-300 mb-1">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] px-3.5 py-2.5 text-xs text-slate-200 focus:border-[#7DB7E8] focus:outline-none font-mono"
              />
            </div>

            <div className="flex gap-3 pt-1">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] py-2.5 font-mono text-xs font-bold text-[#080B0F] shadow-[0_0_20px_rgba(125,183,232,0.2)] transition-all hover:bg-[#9BC7EA] disabled:opacity-50"
              >
                {loading ? 'Authenticating...' : 'Sign In →'}
              </button>
              <Link
                to="/signup"
                className="flex-1 rounded-lg border border-[#7DB7E8]/30 bg-transparent py-2.5 font-mono text-xs font-bold text-[#7DB7E8] text-center transition-all hover:bg-[#7DB7E8]/10"
              >
                Sign Up
              </Link>
            </div>
          </form>
        </div>

        <div className="text-center text-xs text-slate-500 font-mono">
          <Link to="/" className="hover:text-slate-300">
            ← Return to Public Landing Page
          </Link>
        </div>
      </div>
    </div>
  );
}
