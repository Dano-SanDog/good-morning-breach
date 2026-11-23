import { useEffect, useRef } from "react";

export const riskOrder = ["Critical", "High", "Medium", "Low", "Informational"] as const;

export function formatInZone(value: string, timeZone: string | undefined, options: Intl.DateTimeFormatOptions): string {
  const date = new Date(value);
  try {
    return new Intl.DateTimeFormat(undefined, { ...options, timeZone: timeZone || undefined }).format(date);
  } catch {
    return new Intl.DateTimeFormat(undefined, options).format(date);
  }
}

export function RiskCountBar({ risks }: { risks: readonly string[] }) {
  const counts = new Map<string, number>();
  for (const risk of risks) {
    counts.set(risk, (counts.get(risk) ?? 0) + 1);
  }
  if (risks.length === 0) {
    return null;
  }
  return (
    <ul className="risk-count-bar" aria-label="Stories on this page by risk">
      {riskOrder.filter((risk) => counts.has(risk)).map((risk) => (
        <li
          key={risk}
          className={`risk-count risk-${risk.toLowerCase()}`}
          style={{ flexGrow: counts.get(risk) }}
        >
          {counts.get(risk)} {risk}
        </li>
      ))}
    </ul>
  );
}

type ConfirmDeleteProps = {
  email: string;
  typed: string;
  busy: boolean;
  onTyped: (value: string) => void;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmDeleteDialog({ email, typed, busy, onTyped, onConfirm, onCancel }: ConfirmDeleteProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    cancelRef.current?.focus();
  }, []);
  return (
    <div className="dialog-scrim">
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-dialog-title"
        onKeyDown={(event) => { if (event.key === "Escape") { onCancel(); } }}
      >
        <h2 id="delete-dialog-title">Delete {email}?</h2>
        <p>Their email and Slack webhook are deleted. This can't be undone.</p>
        <label htmlFor="delete-confirm-email">Type the account email to confirm</label>
        <input
          id="delete-confirm-email"
          autoComplete="off"
          value={typed}
          onChange={(event) => onTyped(event.target.value)}
        />
        <div className="dialog-actions">
          <button type="button" className="secondary-button" ref={cancelRef} onClick={onCancel}>Cancel</button>
          <button type="button" className="destructive-button" disabled={busy || typed !== email} onClick={onConfirm}>
            Delete account
          </button>
        </div>
        {typed !== email && <p className="muted">Delete is available after you type the email exactly.</p>}
      </div>
    </div>
  );
}

export function IdleWarningDialog({ onStay }: { onStay: () => void }) {
  const stayRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    stayRef.current?.focus();
  }, []);
  return (
    <div className="dialog-scrim">
      <div className="dialog" role="alertdialog" aria-modal="true" aria-labelledby="idle-dialog-title">
        <h2 id="idle-dialog-title">Still there?</h2>
        <p>You will be signed out in about two minutes because of inactivity.</p>
        <div className="dialog-actions">
          <button type="button" className="primary-button" ref={stayRef} onClick={onStay}>Stay signed in</button>
        </div>
      </div>
    </div>
  );
}
