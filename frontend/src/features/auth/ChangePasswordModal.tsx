/**
 * Change Password modal for authenticated analysts.
 * Strictly styled in SnareSight Obsidian (#000F08) and Crimson (#FB3640).
 */

import React, { useState } from 'react';
import { authApi } from '../../services/authApi';

interface ChangePasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ChangePasswordModal: React.FC<ChangePasswordModalProps> = ({ isOpen, onClose }) => {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters in length');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New password and confirmation do not match');
      return;
    }

    setSubmitting(true);
    try {
      await authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setSuccess('Operator password rotated successfully.');
      setTimeout(() => {
        onClose();
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
        setSuccess(null);
      }, 1500);
    } catch (err: any) {
      setError(err.message || 'Failed to update operator password');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#000F08]/80 backdrop-blur-md p-4 selection:bg-[#FB3640] selection:text-[#000F08]">
      <div className="bg-[#000F08] border border-[#FB3640]/30 rounded-2xl max-w-md w-full p-6 shadow-crimson-lg text-[#FB3640]">
        <div className="flex justify-between items-center mb-5 pb-3 border-b border-[#FB3640]/20">
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FB3640]" />
            <h2 className="text-sm font-black tracking-wider uppercase text-[#FB3640]">
              Rotate Operator Passphrase
            </h2>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 rounded-lg bg-[#000F08] border border-[#FB3640]/30 hover:border-[#FB3640] text-[#FB3640] text-xs flex items-center justify-center transition-colors"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-[#FB3640]/10 border border-[#FB3640]/40 text-[#FB3640] text-xs flex items-center gap-2">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="mb-4 p-3 rounded-xl bg-[#FB3640]/15 border border-[#FB3640]/50 text-[#FB3640] text-xs font-semibold flex items-center gap-2">
            <span>✓</span>
            <span>{success}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-[#FB3640]/80 mb-1 font-semibold">Current Passphrase</label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full bg-[#000F08] border border-[#FB3640]/30 rounded-xl px-3.5 py-2.5 text-[#FB3640] placeholder-[#FB3640]/30 focus:outline-none focus:border-[#FB3640] font-mono"
            />
          </div>

          <div>
            <label className="block text-[#FB3640]/80 mb-1 font-semibold">New Passphrase (min 8 chars)</label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full bg-[#000F08] border border-[#FB3640]/30 rounded-xl px-3.5 py-2.5 text-[#FB3640] placeholder-[#FB3640]/30 focus:outline-none focus:border-[#FB3640] font-mono"
            />
          </div>

          <div>
            <label className="block text-[#FB3640]/80 mb-1 font-semibold">Confirm New Passphrase</label>
            <input
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full bg-[#000F08] border border-[#FB3640]/30 rounded-xl px-3.5 py-2.5 text-[#FB3640] placeholder-[#FB3640]/30 focus:outline-none focus:border-[#FB3640] font-mono"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#FB3640]/20">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-[#000F08] border border-[#FB3640]/30 hover:border-[#FB3640] text-xs text-[#FB3640] font-semibold transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-5 py-2 rounded-xl bg-[#FB3640] hover:bg-[#FB3640]/90 text-[#000F08] text-xs font-black tracking-wide uppercase transition-all shadow-crimson-sm disabled:opacity-50"
            >
              {submitting ? 'Updating...' : 'Confirm Rotation'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
