import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { Badge, Preview } from './Shared';
import type { Snapshot } from '../types';
describe('reviewed execution preview', () => {
  it('renders command text safely and warns on elevated identities', () => {
    const snapshot = {
      test_name: 'Test',
      technique: 'T1082',
      hostname: 'WIN-TEST-01',
      account: '.\\atomic-admin',
      privilege: 'elevated',
      risk_level: 'medium',
      action: 'execute',
      timeout_seconds: 120,
      source_revision: 'pinned',
      expected_sid: 'S-1-5-21-1',
      content_sha256: 'abc',
      definition: { executor: { command: '<img src=x onerror=alert(1)>', name: 'powershell' } },
    } as Snapshot;
    const { container } = render(<Preview snapshot={snapshot} />);
    expect(screen.getByText(/Elevated execution requires/)).toBeVisible();
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible();
    expect(container.querySelector('img')).toBeNull();
  });
  it('distinguishes acceptance from completed execution', () => {
    render(<Badge value="pending_approval" />);
    expect(screen.getByText('pending approval')).toBeVisible();
    expect(screen.queryByText('succeeded')).toBeNull();
  });
});
