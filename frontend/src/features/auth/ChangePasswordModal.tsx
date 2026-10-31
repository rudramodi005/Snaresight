/**
 * Change Password modal for authenticated analysts.
 * Styled in SnareSight Security Palette: #181A2F, #242E49, #37415C, #FDA481, #B4182D, #54162B.
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#181A2F]/80 backdrop-blur-md p-4 selection:bg-[#B4182D] selection:text-white">
      <div className="bg-[#242E49] border border-[#37415C] rounded-2xl max-w-md w-full p-6 shadow-2xl text-[#E2E8F0]">
        <div className="flex justify-between items-center mb-5 pb-3 border-b border-[#37415C]">
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#B4182D]" />
            <h2 className="text-sm font-black tracking-wider uppercase text-white">
              Rotate Operator Passphrase
            </h2>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 rounded-lg bg-[#181A2F] border border-[#37415C] hover:border-[#FDA481] text-[#94A3B8] hover:text-[#FDA481] text-xs flex items-center justify-center transition-colors"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-[#54162B] border border-[#B4182D] text-[#FDA481] text-xs flex items-center gap-2">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="mb-4 p-3 rounded-xl bg-[#181A2F] border border-[#10B981] text-[#10B981] text-xs font-semibold flex items-center gap-2">
            <span>✓</span>
            <span>{success}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-[#CBD5E1] mb-1 font-semibold">Current Passphrase</label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full bg-[#181A2F] border border-[#37415C] rounded-xl px-3.5 py-2.5 text-white placeholder-[#94A3B8]/50 focus:outline-none focus:border-[#FDA481] font-mono"
            />
          </div>

          <div>
            <label className="block text-[#CBD5E1] mb-1 font-semibold">New Passphrase (min 8 chars)</label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full bg-[#181A2F] border border-[#37415C] rounded-xl px-3.5 py-2.5 text-white placeholder-[#94A3B8]/50 focus:outline-none focus:border-[#FDA481] font-mono"
            />
          </div>

          <div>
            <label className="block text-[#CBD5E1] mb-1 font-semibold">Confirm New Passphrase</label>
            <input
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full bg-[#181A2F] border border-[#37415C] rounded-xl px-3.5 py-2.5 text-white placeholder-[#94A3B8]/50 focus:outline-none focus:border-[#FDA481] font-mono"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#37415C]">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-[#181A2F] border border-[#37415C] hover:border-[#FDA481] text-xs text-[#CBD5E1] hover:text-[#FDA481] font-semibold transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-5 py-2 rounded-xl bg-[#B4182D] hover:bg-[#B4182D]/90 text-white text-xs font-black tracking-wide uppercase transition-all shadow-crimson-sm disabled:opacity-50"
            >
              {submitting ? 'Updating...' : 'Confirm Rotation'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
