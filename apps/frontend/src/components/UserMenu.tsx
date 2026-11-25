import { useEffect, useId, useRef, useState } from 'react';
import { LogOut, UserRound } from 'lucide-react';

export default function UserMenu({ username }: { username: string }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const signOut = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    signOut.current?.focus();
    function outside(event: PointerEvent) {
      if (event.target instanceof Node && !root.current?.contains(event.target)) setOpen(false);
    }
    function escape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpen(false);
        trigger.current?.focus();
      }
    }
    document.addEventListener('pointerdown', outside);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('keydown', escape);
    };
  }, [open]);
  return (
    <div
      className="user-menu"
      ref={root}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <button
        type="button"
        className="profile-circle"
        aria-label="User menu"
        aria-expanded={open}
        aria-controls={panelId}
        ref={trigger}
        onClick={() => setOpen((value) => !value)}
      >
        <UserRound size={16} aria-hidden="true" />
      </button>
      {open && (
        <div id={panelId} className="user-menu-panel" role="region" aria-label="User account">
          <small>Signed in as</small>
          <span className="user-menu-username">{username}</span>
          <form method="POST" action="/auth/logout">
            <button type="submit" className="button ghost" ref={signOut}>
              <LogOut size={16} aria-hidden="true" />
              Sign out
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
