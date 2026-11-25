import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Atom, ArrowRight, RefreshCw, ShieldCheck } from 'lucide-react';
import { api, APIError, AUTHORIZATION_LOST } from '../services/api';
import type { User } from '../types';
import { Button } from './ui/button';

type Authorization = {
  status: 'checking' | 'authorized' | 'signed-out' | 'forbidden' | 'unavailable';
  deadline?: number;
  user?: User;
};

export default function AuthGate({ children }: { children: (user: User) => ReactNode }) {
  const [authorization, setAuthorization] = useState<Authorization>({ status: 'checking' });
  const generation = useRef(0);
  const check = useCallback(async () => {
    const current = ++generation.current;
    const started = performance.now();
    try {
      const user = await api<User>('/me');
      if (generation.current !== current) return;
      if (user.mode !== 'real' || user.dev_auth || !user.roles.includes('viewer')) {
        setAuthorization({ status: 'forbidden' });
      } else if (user.session_expires_in != null && user.session_expires_in <= 0) {
        setAuthorization({ status: 'signed-out' });
      } else {
        setAuthorization({
          status: 'authorized',
          user,
          deadline:
            user.session_expires_in != null ? started + user.session_expires_in * 1000 : undefined,
        });
      }
    } catch (error) {
      if (generation.current !== current) return;
      setAuthorization({
        status:
          error instanceof APIError && error.status === 401
            ? 'signed-out'
            : error instanceof APIError && error.status === 403
              ? 'forbidden'
              : 'unavailable',
      });
    }
  }, []);
  useEffect(() => {
    const lost = (event: Event) => {
      generation.current++;
      const status = (event as CustomEvent<{ status: number }>).detail.status;
      setAuthorization({
        status: status === 503 ? 'unavailable' : status === 403 ? 'forbidden' : 'signed-out',
      });
    };
    window.addEventListener(AUTHORIZATION_LOST, lost);
    void check();
    return () => {
      generation.current++;
      window.removeEventListener(AUTHORIZATION_LOST, lost);
    };
  }, [check]);
  useEffect(() => {
    const visible = () => {
      if (!document.hidden) void check();
    };
    window.addEventListener('focus', visible);
    window.addEventListener('pageshow', visible);
    document.addEventListener('visibilitychange', visible);
    return () => {
      window.removeEventListener('focus', visible);
      window.removeEventListener('pageshow', visible);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [check]);
  useEffect(() => {
    if (authorization.status !== 'authorized' || authorization.deadline == null) return;
    const timer = setTimeout(
      () => {
        generation.current++;
        setAuthorization({ status: 'signed-out' });
      },
      Math.max(0, authorization.deadline - performance.now()),
    );
    return () => clearTimeout(timer);
  }, [authorization]);
  if (authorization.status === 'authorized' && authorization.user)
    return children(authorization.user);
  return (
    <main className="login-screen">
      <section className="login-card" aria-label="Atomic Control sign-in">
        <div className="login-mark">
          <Atom size={38} />
        </div>
        <h1>Atomic Control</h1>
        <p className="login-subtitle">Security validation platform</p>
        <ShieldCheck size={24} />
        <h2>
          {authorization.status === 'checking' ? 'Checking authorization…' : 'Sign in to continue'}
        </h2>
        <p role="status">
          {authorization.status === 'checking'
            ? 'Verifying your control-plane session.'
            : authorization.status === 'forbidden'
              ? 'Your account is not authorized to access this dashboard.'
              : authorization.status === 'unavailable'
                ? 'Unable to verify your session. Retry when the control plane is available.'
                : 'Authentication is required to access the control plane.'}
        </p>
        {authorization.status !== 'checking' && (
          <>
            <a className="button primary" href="/auth/login">
              Sign in with SSO <ArrowRight size={16} />
            </a>
            {authorization.status === 'unavailable' && (
              <Button variant="outline" onClick={() => void check()}>
                <RefreshCw size={15} />
                Retry connection
              </Button>
            )}
            <small>Authorized sessions last up to 24 hours.</small>
          </>
        )}
      </section>
    </main>
  );
}
