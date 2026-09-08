import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { Icon } from '@/components/Icon';

export const Navbar: React.FC = () => {
  const navigate = useNavigate();
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'border-b border-[#222B35] bg-[#080B0F]/90 backdrop-blur-md shadow-lg py-3'
          : 'bg-transparent py-5'
      }`}
    >
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Left: Brand Logo */}
        <Link to="/" className="flex items-center gap-3 group">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#7DB7E8]/30 bg-[#11171E] text-[#7DB7E8] transition-colors group-hover:border-[#7DB7E8]">
            <Icon name="shield" size={20} />
          </div>
          <div className="flex flex-col">
            <span className="font-mono text-base font-bold tracking-wider text-slate-100">
              BLINDSPOT
            </span>
            <span className="font-mono text-[10px] font-semibold tracking-widest text-[#7DB7E8] -mt-1">
              ECDAT
            </span>
          </div>
        </Link>

        {/* Center Nav Links (Desktop) */}
        <div className="hidden items-center gap-8 md:flex text-xs font-medium text-slate-300">
          <a href="#product" className="transition-colors hover:text-[#7DB7E8]">
            Product
          </a>
          <a href="#how-it-works" className="transition-colors hover:text-[#7DB7E8]">
            How It Works
          </a>
          <a href="#features" className="transition-colors hover:text-[#7DB7E8]">
            Features
          </a>
          <a href="#mosca" className="transition-colors hover:text-[#7DB7E8]">
            Mosca Math
          </a>
          <a href="#cbom" className="transition-colors hover:text-[#7DB7E8]">
            CBOM Standard
          </a>
          <a href="#use-cases" className="transition-colors hover:text-[#7DB7E8]">
            Use Cases
          </a>
        </div>

        {/* Right CTA Actions */}
        <div className="hidden items-center gap-4 md:flex">
          <button
            onClick={() => navigate('/login')}
            className="text-xs font-medium text-slate-300 transition-colors hover:text-white"
          >
            Sign In
          </button>
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8] px-4 py-2 text-xs font-semibold text-[#080B0F] shadow-[0_0_15px_rgba(125,183,232,0.2)] transition-all hover:bg-[#9BC7EA] hover:shadow-[0_0_20px_rgba(125,183,232,0.4)]"
          >
            <span>Launch ECDAT</span>
            <Icon name="arrow-right" size={14} />
          </button>
        </div>

        {/* Mobile Hamburger Toggle */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="p-2 text-slate-400 hover:text-white md:hidden"
        >
          <Icon name={mobileMenuOpen ? 'close' : 'menu'} size={22} />
        </button>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen ? (
        <div className="border-b border-[#222B35] bg-[#0C1117] px-6 py-6 md:hidden space-y-4">
          <div className="flex flex-col space-y-3 text-sm font-medium text-slate-300">
            <a href="#product" onClick={() => setMobileMenuOpen(false)}>Product</a>
            <a href="#how-it-works" onClick={() => setMobileMenuOpen(false)}>How It Works</a>
            <a href="#features" onClick={() => setMobileMenuOpen(false)}>Features</a>
            <a href="#mosca" onClick={() => setMobileMenuOpen(false)}>Mosca Math</a>
            <a href="#cbom" onClick={() => setMobileMenuOpen(false)}>CBOM Standard</a>
            <a href="#use-cases" onClick={() => setMobileMenuOpen(false)}>Use Cases</a>
          </div>
          <div className="pt-4 border-t border-[#222B35] flex flex-col gap-3">
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                navigate('/login');
              }}
              className="w-full text-center py-2 text-sm text-slate-300"
            >
              Sign In
            </button>
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                navigate('/dashboard');
              }}
              className="w-full text-center py-2.5 rounded-lg bg-[#7DB7E8] text-xs font-semibold text-[#080B0F]"
            >
              Launch ECDAT →
            </button>
          </div>
        </div>
      ) : null}
    </nav>
  );
};
