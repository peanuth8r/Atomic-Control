import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Button } from './ui/button';

type Settings = { enrollment_token_minutes: number };

export default function AgentEnrollmentSettings() {
  const [minutes, setMinutes] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  useEffect(() => {
    let active = true;
    api<Settings>('/admin/agent-settings')
      .then((value) => active && setMinutes(String(value.enrollment_token_minutes)))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, []);
  return (
    <section className="panel panel-content">
      <h2>Agent enrollment</h2>
      <p>
        Set how long a new initial installation token remains valid. Tokens are single-use. Changes
        apply to newly generated packages and tokens; existing tokens keep their expiry.
      </p>
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          setSaving(true);
          setError('');
          setMessage('');
          try {
            const result = await api<Settings>('/admin/agent-settings', {
              method: 'PUT',
              body: JSON.stringify({ enrollment_token_minutes: Number(minutes) }),
            });
            setMinutes(String(result.enrollment_token_minutes));
            setMessage(
              `Saved. New enrollment tokens expire after ${result.enrollment_token_minutes} minutes.`,
            );
          } catch (e) {
            setError((e as Error).message);
          } finally {
            setSaving(false);
          }
        }}
      >
        <label htmlFor="enrollment-token-minutes">
          Initial installation token lifetime (minutes)
        </label>
        <input
          className="agent-text-input"
          id="enrollment-token-minutes"
          type="number"
          min="5"
          max="1440"
          step="1"
          required
          disabled={loading || saving}
          value={minutes}
          onChange={(event) => {
            setMinutes(event.target.value);
            setMessage('');
          }}
        />
        <p className="subtle">Default: 60 minutes. Allowed range: 5–1,440 minutes.</p>
        <Button disabled={loading || saving || !minutes}>
          {saving ? 'Saving…' : 'Save enrollment settings'}
        </Button>
      </form>
      {error && (
        <p role="alert" className="warning">
          {error}
        </p>
      )}
      {message && <p role="status">{message}</p>}
    </section>
  );
}
