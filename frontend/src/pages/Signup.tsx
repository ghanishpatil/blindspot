import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { Icon } from '@/components/Icon';

export default function Signup() {
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);

    // For the demo, sign up navigates to dashboard directly.
    // When Firebase Auth is wired, this calls createUserWithEmailAndPassword.
    setTimeout(() => {
      setLoading(false);
      navigate('/dashboard');
    }, 500);
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
          <h1 className="font-mono text-2xl font-bold tracking-wider text-slate-100">CREATE ACCOUNT</h1>
          <p className="font-mono text-xs uppercase tracking-widest text-[#7DB7E8]">
            Blindspot ECDAT
          </p>
        </div>

        {/* Signup Form Box */}
        <div className="rounded-2xl border border-[#222B35] bg-[#11171E] p-8 shadow-2xl space-y-6">
          {error ? (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
              {error}
            </div>
          ) : null}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-xs font-mono font-medium text-slate-300 mb-1">
                Full Name
              </label>
              <input
                id="name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Security Engineer"
                required
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none font-mono"
              />
            </div>

            <div>
              <label htmlFor="signup-email" className="block text-xs font-mono font-medium text-slate-300 mb-1">
                Email Address
              </label>
              <input
                id="signup-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@organization.com"
                required
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none font-mono"
              />
            </div>

            <div>
              <label htmlFor="signup-password" className="block text-xs font-mono font-medium text-slate-300 mb-1">
                Password
              </label>
              <input
                id="signup-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Min 6 characters"
                required
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none font-mono"
              />
            </div>

            <div>
              <label htmlFor="confirm-password" className="block text-xs font-mono font-medium text-slate-300 mb-1">
                Confirm Password
              </label>
              <input
                id="confirm-password"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="Re-enter password"
                required
                className="w-full rounded-lg border border-[#222B35] bg-[#080B0F] px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-[#7DB7E8] focus:outline-none font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] py-2.5 font-mono text-xs font-bold text-[#080B0F] shadow-[0_0_20px_rgba(125,183,232,0.2)] transition-all hover:bg-[#9BC7EA] disabled:opacity-50"
            >
              {loading ? 'Creating Account...' : 'Create Account →'}
            </button>
          </form>

          <div className="pt-4 text-center text-xs text-slate-400 border-t border-[#222B35]">
            Already have an account?{' '}
            <Link to="/login" className="text-[#7DB7E8] hover:underline font-mono font-semibold">
              Sign In
            </Link>
          </div>
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
