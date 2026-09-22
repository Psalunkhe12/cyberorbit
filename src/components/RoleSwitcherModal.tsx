import React from 'react';
import { Operator } from '../types';
import { OPERATOR_PROFILES } from '../data/mockData';
import { X, Check, Shield } from 'lucide-react';

interface RoleSwitcherModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentOperator: Operator;
  onSelectOperator: (op: Operator) => void;
}

export const RoleSwitcherModal: React.FC<RoleSwitcherModalProps> = ({
  isOpen,
  onClose,
  currentOperator,
  onSelectOperator,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs grid place-items-center p-4">
      <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-[#d4deda] relative animate-in fade-in zoom-in-95 duration-200">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-[#6c8582] hover:text-[#253835] bg-[#dce3e0] p-1.5 rounded-full border-none cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2 mb-1">
          <Shield className="w-5 h-5 text-[#d49b28]" />
          <h3 className="font-display text-lg font-bold text-[#253835]">
            Switch Operator Profile
          </h3>
        </div>
        <p className="text-xs text-[#6c8582] mb-5">
          Select an active analyst profile to update role-based authorization and activity logs.
        </p>

        <div className="flex flex-col gap-3">
          {OPERATOR_PROFILES.map((op) => {
            const isSelected = op.id === currentOperator.id;
            return (
              <button
                key={op.id}
                onClick={() => {
                  onSelectOperator(op);
                  onClose();
                }}
                className={`flex items-center justify-between p-3.5 rounded-xl border-2 text-left cursor-pointer transition-all ${
                  isSelected
                    ? 'border-[#d49b28] bg-[#d49b28]/10'
                    : 'border-[#d4deda] hover:border-[#334d4a] bg-white'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-10 h-10 rounded-full border-2 grid place-items-center font-bold text-sm text-[#334d4a]"
                    style={{ borderColor: op.avatarColor, backgroundColor: `${op.avatarColor}20` }}
                  >
                    {op.initials}
                  </div>
                  <div>
                    <b className="block text-sm text-[#253835] font-bold">{op.name}</b>
                    <small className="text-xs text-[#6c8582] block">{op.role}</small>
                    <span className="text-[10px] font-mono-code text-[#334d4a] block mt-0.5">
                      {op.shift}
                    </span>
                  </div>
                </div>

                {isSelected && (
                  <div className="w-6 h-6 rounded-full bg-[#d49b28] text-white grid place-items-center">
                    <Check className="w-3.5 h-3.5" />
                  </div>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
