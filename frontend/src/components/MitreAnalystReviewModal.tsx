import React, { useState } from 'react';
import { DetectionMapping, ReviewAction } from '../types/mitre';

interface MitreAnalystReviewModalProps {
  mapping: DetectionMapping | null;
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (mappingId: string, action: ReviewAction, comment: string) => Promise<void>;
}

export const MitreAnalystReviewModal: React.FC<MitreAnalystReviewModalProps> = ({
  mapping,
  isOpen,
  onClose,
  onSubmit,
}) => {
  const [action, setAction] = useState<ReviewAction>('ACCEPT');
  const [comment, setComment] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen || !mapping) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!comment.trim()) {
      setError('Please provide a substantive review justification comment.');
      return;
    }
    setError(null);
    setIsSubmitting(true);
    try {
      await onSubmit(mapping.mapping_id, action, comment.trim());
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Failed to submit review.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-lg w-full p-6 text-slate-100 space-y-4 shadow-xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-base font-semibold text-slate-100">
            Analyst Review: {mapping.subtechnique_id || mapping.technique_id}
          </h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 text-lg">
            ✕
          </button>
        </div>

        <p className="text-xs text-slate-400">
          Review the automated association between detection rule{' '}
          <strong className="text-cyan-400 font-mono">{mapping.rule_id}</strong> and technique{' '}
          <strong className="text-cyan-400 font-mono">{mapping.technique_id}</strong>.
        </p>

        {error && (
          <div className="p-3 bg-rose-950/40 border border-rose-800/80 rounded text-rose-300 text-xs">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Review Action
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setAction('ACCEPT')}
                className={`py-2 px-3 text-xs font-medium rounded border transition-colors ${
                  action === 'ACCEPT'
                    ? 'bg-emerald-600 border-emerald-500 text-white'
                    : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Accept
              </button>
              <button
                type="button"
                onClick={() => setAction('REQUEST_MORE_EVIDENCE')}
                className={`py-2 px-3 text-xs font-medium rounded border transition-colors ${
                  action === 'REQUEST_MORE_EVIDENCE'
                    ? 'bg-amber-600 border-amber-500 text-white'
                    : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Need Evidence
              </button>
              <button
                type="button"
                onClick={() => setAction('REJECT')}
                className={`py-2 px-3 text-xs font-medium rounded border transition-colors ${
                  action === 'REJECT'
                    ? 'bg-rose-600 border-rose-500 text-white'
                    : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Reject
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Reviewer Justification & Notes *
            </label>
            <textarea
              rows={4}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Provide clear rationale for your assessment (e.g., observed packet patterns match brute force signature; decoy simulation confirmed)..."
              className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
              required
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-4 py-2 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 text-xs font-medium rounded bg-cyan-600 hover:bg-cyan-500 text-white transition-colors disabled:opacity-50"
            >
              {isSubmitting ? 'Submitting...' : 'Confirm Review'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

