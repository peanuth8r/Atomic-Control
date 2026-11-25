import type { Actor, AtomicTest } from '../types';

export function actorMatchesPlatform(actor: Actor, test?: AtomicTest): boolean {
  return (
    !!test &&
    actor.registration_state !== 'retired' &&
    test.definition.supported_platforms.includes(actor.os)
  );
}

export function actorExclusions(actor: Actor, test?: AtomicTest): string[] {
  if (actor.registration_state === 'retired') return ['Actor is permanently retired'];
  const reasons: string[] = [];
  if (!actor.enabled) reasons.push('Actor is disabled');
  if (!actor.online) reasons.push('No recent healthy heartbeat');
  if (
    actor.delivery_mode !== 'on_demand' &&
    ['pending', 'applying'].includes(actor.catalog?.status || '')
  )
    reasons.push('Catalog installation is pending');
  if (actor.delivery_mode !== 'on_demand' && actor.catalog?.status === 'failed')
    reasons.push('Catalog installation failed; retry under Actors → Configure catalog');
  if (['purge_failed', 'orphaned'].includes(actor.workspace_status || ''))
    reasons.push('Downloaded files remain; resolve agent removal failure');
  if (!test) return reasons;
  if (!test.approved) reasons.push('Test definition is not approved');
  if (!test.definition.supported_platforms.includes(actor.os))
    reasons.push(`Test does not support ${actor.os}`);
  if (
    !(actor.os === 'linux' ? ['bash', 'sh'] : ['powershell', 'command_prompt']).includes(
      test.definition.executor.name,
    )
  )
    reasons.push('Executor is unsupported on this actor');
  if (actor.delivery_mode === 'on_demand') {
    if (actor.artifact_protocol !== 1) reasons.push('Agent needs an on-demand delivery update');
  } else if (test.catalog_source === 'custom') {
    reasons.push('Custom tests require on-demand delivery');
  } else if (!actor.revision) reasons.push('No pinned catalog revision reported');
  else if (actor.revision !== test.revision)
    reasons.push('Catalog revision differs from the approved test');
  const matching = actor.profiles.filter(
    (profile) =>
      profile.enabled &&
      test.allowed_profiles.includes(profile.profile_key) &&
      (!test.definition.executor.elevation_required || profile.privilege === 'elevated'),
  );
  if (!matching.length) reasons.push('No registered profile matches the test approval');
  else if (!matching.some((profile) => profile.healthy))
    reasons.push('Matching execution profile is not validated and healthy');
  return reasons;
}
