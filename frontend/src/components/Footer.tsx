import React from 'react';
import { Link } from 'react-router-dom';

import { Icon } from '@/components/Icon';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-[#222B35] bg-[#080B0F] text-slate-400">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid gap-8 md:grid-cols-4">
          {/* Col 1: Brand Info */}
          <div className="space-y-4 md:col-span-2">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#7DB7E8]/30 bg-[#11171E] text-[#7DB7E8]">
                <Icon name="shield" size={18} />
              </div>
              <div className="flex flex-col">
                <span className="font-mono text-base font-bold tracking-wider text-slate-100">
                  BLINDSPOT
                </span>
                <span className="font-mono text-[10px] font-semibold tracking-widest text-[#7DB7E8] -mt-1">
                  ECDAT
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-400 max-w-md leading-relaxed">
              Enterprise Cryptographic Discovery & Analysis Tool (ECDAT). Automated discovery of cryptographic artefacts across source code and dependencies, standardized CycloneDX CBOM construction, and quantum risk assessment via Mosca&apos;s inequality.
            </p>

            <div className="font-mono text-[11px] text-slate-500">
              <span className="rounded border border-slate-800 bg-[#0C1117] px-2.5 py-1">
                SIH 2026 — Problem Statement 26164
              </span>
            </div>
          </div>

          {/* Col 2: Navigation */}
          <div>
            <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200 mb-3">
              Platform
            </h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li><a href="#product" className="hover:text-[#7DB7E8]">Cryptographic Posture</a></li>
              <li><a href="#how-it-works" className="hover:text-[#7DB7E8]">5-Stage Pipeline</a></li>
              <li><a href="#mosca" className="hover:text-[#7DB7E8]">Mosca Risk Framework</a></li>
              <li><a href="#cbom" className="hover:text-[#7DB7E8]">CycloneDX CBOM v1.6</a></li>
              <li><Link to="/scan" className="hover:text-[#7DB7E8]">Live AST Scanner</Link></li>
            </ul>
          </div>

          {/* Col 3: Resources & Governance */}
          <div>
            <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200 mb-3">
              Standards & Reference
            </h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li><a href="https://csrc.nist.gov/pqc" target="_blank" rel="noreferrer" className="hover:text-[#7DB7E8]">NIST FIPS 203 (ML-KEM)</a></li>
              <li><a href="https://csrc.nist.gov/pqc" target="_blank" rel="noreferrer" className="hover:text-[#7DB7E8]">NIST FIPS 204 (ML-DSA)</a></li>
              <li><a href="https://cyclonedx.org" target="_blank" rel="noreferrer" className="hover:text-[#7DB7E8]">CycloneDX Cryptography Spec</a></li>
              <li><a href="https://iqc.uwaterloo.ca" target="_blank" rel="noreferrer" className="hover:text-[#7DB7E8]">Mosca Risk Methodology</a></li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="mt-12 flex flex-wrap items-center justify-between gap-4 border-t border-[#222B35] pt-6 text-xs text-slate-500">
          <p>&copy; {new Date().getFullYear()} Blindspot Security. All rights reserved.</p>
          <div className="flex items-center gap-6 font-mono text-[11px]">
            <span className="text-[#7DB7E8]">"You cannot migrate cryptography you cannot find."</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
