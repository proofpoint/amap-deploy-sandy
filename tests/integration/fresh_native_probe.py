"""Real native fresh startup, active pause, and optional queued-before-birth restart.

Run explicitly with --adapter CHECKOUT --connector PINNED_CORE --output FILE
and optionally --queued-before-birth. Uses the core integration synthetic
localhost provider and disposable state, never fleet submissions or user auth.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest import mock


async def probe(args):
    sys.path[:0] = [str(args.adapter), str(args.connector / 'src'),
                   str(args.connector / 'tests/integration')]
    import codex_assets as assets
    import codex_fleet as fleet
    import codex_fresh as fresh
    from unified_probe import Terminal, until
    from unified_runtime_probe import configuration, publish

    build = subprocess.check_output(['codex', '--version'], text=True).strip()
    evidence = {'codex_version': build, 'external_inference': False,
                'user_auth_used': False, 'fleet_submissions': 0,
                'probe_assertions_passed': False,
                'adapter_source_sha256': hashlib.sha256((args.adapter / 'codex_fresh.py').read_bytes()).hexdigest(),
                'scope': 'real native adapter startup; disposable local synthetic inference; no Sandy host acceptance'}
    with tempfile.TemporaryDirectory(prefix='fresh-native-', dir=args.temp_root) as td:
        root = Path(td)
        original, _, provider = configuration(root, build, hold_first=True)
        state, payload = original.state_dir, root / 'payload'
        state.rmdir()  # Only the empty disposable fixture directory exists.
        assets.install(payload, original.operator_instructions,
                       original.trusted_config_file, dry_run=False)
        env = dict(provider.env, CODEX_MODEL='synthetic-model',
                   SANDY_SKIP_PERMISSIONS='true',
                   PYTHONPATH=str(args.connector / 'src'))
        env[fleet.EXPORT] = 'unified'
        env.update(AMAP_INBOX_DIR=str(root / 'mail'),
                   AMAP_PEER_DIR=str(root / 'peer'),
                   AMAP_OUTBOX_DIR=str(root / 'outbox'))
        service = terminal = task = None
        pending = None
        try:
            with mock.patch.dict(os.environ, env, clear=True):
                if args.queued_before_birth:
                    pending = publish(original, 'peer', 'synthetic_before_birth')
                    evidence['pending_published_before_birth'] = True
                born = fresh.birth(state, {'sandbox_name': original.instance_id,
                                          'workspace': str(root)}, env)
                context = {**born['identity'], 'payload': str(payload),
                           'self_address': original.self_address,
                           'codex_version': build}
                fresh.prepare(state, payload, context, env)
                fresh.publish_request(state, env)
                assert not (state / 'journal.sqlite3').exists()
                assert provider.requests == []
                argv = ['codex', '--sandbox', 'danger-full-access',
                        '--ask-for-approval', 'never', '--no-daemon',
                        '--model', 'synthetic-model']
                if not args.queued_before_birth:
                    argv += ['--', 'SYNTHETIC_HUMAN']
                terminal = Terminal(['python3', str(args.adapter / 'codex_fresh.py'),
                                     '--state', str(state), '--payload', str(payload),
                                     'launch-pane', '--', *argv], env, root)
                await until(lambda: (state / fresh.SELECTION).exists(), terminal)
                assert not (state / 'journal.sqlite3').exists()
                assert provider.requests == []
                evidence['zero_native_work_before_full_argv'] = True
                service = fresh.service_class()(fresh.config_at(state),
                                                state / 'controller.toml', env=env)
                observed_ticks = []
                original_tick = service.tick
                async def observed_tick():
                    observed_ticks.append({'at': time.monotonic(),
                                           'paused': (state / 'adapter-pause.json').exists()})
                    await original_tick()
                    observed_ticks[-1]['returned'] = True
                service.tick = observed_tick
                task = asyncio.create_task(service.run())
                await until(provider.arrived.is_set, terminal)
                evidence['real_protected_wrapper_started_owned_turn'] = True
                evidence['owned_turn_source'] = 'queued_peer' if pending else 'human'
                evidence['initialization_phase'] = fresh.initialization(
                    state, fresh.load_plan(state))['phase']
                (state / 'adapter-pause.json').write_text(json.dumps(
                    {'schema': 1, 'state': 'paused', 'note': 'Synthetic active-work pause'}))
                await asyncio.sleep(max(.8, service.config.poll_interval_ms / 1000 * 3))
                evidence['pause_preserves_service'] = not task.done() and not service.stop_requested.is_set()
                evidence['pause_preserves_owned_backend'] = service.backend.process.returncode is None
                evidence['native_client_open'] = not service.backend.client.closed
                evidence['model_requests'] = len(provider.requests)
                evidence['poll_interval_ms'] = service.config.poll_interval_ms
                evidence['ticks'] = observed_ticks
                if task.done():
                    failure = task.exception()
                    evidence['service_exit'] = type(failure).__name__ + ': ' + str(failure)
                args.output.write_text(json.dumps(evidence, indent=2) + '\n')
                assert evidence['pause_preserves_service'], evidence
                assert evidence['pause_preserves_owned_backend'], evidence
                assert evidence['native_client_open'], evidence
                if pending:
                    (state / 'adapter-pause.json').unlink()
                    provider.release.set()
                    await until(lambda: service.journal.event(pending)['state'] == 'finished', terminal)
                    assert len(provider.requests) == 1
                    thread = service.journal.thread_id
                    terminal.close()
                    terminal = None
                    service.stop_requested.set()
                    await asyncio.wait_for(task, 10)
                    # New entry, same durable namespace: the genuine core
                    # resumes the owned thread and Scanner must not replay.
                    fresh.publish_request(state, env)
                    fresh.select_pane(state, ['codex', '--sandbox', 'danger-full-access',
                                      '--ask-for-approval', 'never', '--no-daemon',
                                      '--model', 'synthetic-model', 'resume', '--last'], env)
                    service = fresh.service_class()(fresh.config_at(state), state / 'controller.toml', env=env)
                    await service.start()
                    assert service.journal.thread_id == thread
                    for _ in range(3):
                        await service.tick()
                    assert service.journal.event(pending)['state'] == 'finished'
                    assert len(provider.requests) == 1
                    evidence['queued_before_birth_finished_once'] = True
                    evidence['same_canonical_restart_without_replay'] = True
                    task = None
                    await service.close()
                    service = None
                evidence['probe_assertions_passed'] = True
                args.output.write_text(json.dumps(evidence, indent=2) + '\n')
        except BaseException as exc:
            evidence['failure'] = type(exc).__name__ + ': ' + str(exc)
            args.output.write_text(json.dumps(evidence, indent=2) + '\n')
            raise
        finally:
            provider.release.set()
            if terminal:
                terminal.close()
            if service:
                service.stop_requested.set()
            if task:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(task, 10)
            elif service:
                with contextlib.suppress(Exception):
                    await service.close()
            await provider.close()
    print(json.dumps(evidence))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--connector', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--queued-before-birth', action='store_true')
    parser.add_argument('--temp-root', type=Path, help='Existing directory for disposable probe state')
    asyncio.run(probe(parser.parse_args()))
