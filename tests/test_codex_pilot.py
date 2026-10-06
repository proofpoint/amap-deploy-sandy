import json
import os
from pathlib import Path
import sys
from unittest import mock

import pytest

tomllib = pytest.importorskip("tomllib", reason="optional Codex pilot requires Python 3.11+")

import amap_sandy as deployment
import codex_pilot as pilot
import fleet_policy as fp


def fixture(tmp_path):
    home=tmp_path/'host'; feature=home/'features'/'amap'; feature.mkdir(parents=True)
    policy=fp.default_policy(); policy['fleet_domain']='agents.example.org'
    (feature/'feature.json').write_text(json.dumps(deployment.render_manifest(policy,receives=True)))
    (feature/'router.json').write_text(json.dumps({'state_dir':str(home/'router-state')}))
    (feature/'payload').mkdir(); (feature/'payload'/'relay').write_text('old-relay')
    (feature/'selected.json').write_text(json.dumps({'schema':1,'selected':[{'slug':'b-11111111'},{'slug':'old-22222222'}],'not_selected':[]}))
    boxes=[{'name':name,'path':str(home/'sandboxes'/name),'workspace_path':'/work/'+name,
            'agents':['codex' if name.startswith('c-') else 'claude'],'features':['amap'] if not name.startswith('c-') else []}
           for name in ('b-11111111','old-22222222','c-33333333')]
    codex=tmp_path/'codex'; (codex/'bin').mkdir(parents=True); (codex/'config').mkdir()
    for name in ('inbox-mcp-vol','inbox-submit','_inboxlib.py'): (codex/'bin'/name).write_text('tool')
    (codex/'config'/'operator-instructions.md').write_text('workflow')
    sandy=tmp_path/'sandy'; sandy.mkdir(); (sandy/'managed_exec.py').write_text('helper')
    c,b=boxes[-1],boxes[0]
    return pilot.render(home,boxes,c,b,'fixture-model',codex,sandy,sys.executable,tmp_path/'plan.json',
                        {'manifest':{'top_level_keys':['submounts']}})


def test_preview_preserves_old_edges_state_and_separates_entries(tmp_path):
    plan=fixture(tmp_path)
    common=json.loads(plan['outputs'][str(Path(plan['home'])/'features'/'amap'/'feature.json')])
    assert 'entry' not in common
    assert common['feature']['task_graph']=={'b-11111111':['old-22222222','c-33333333'],
        'old-22222222':['b-11111111'],'c-33333333':['b-11111111']}
    router=json.loads(plan['outputs'][str(Path(plan['home'])/'features'/'amap'/'router.json')])
    assert router['state_dir']==plan['router_state']
    assert router['connector_outcome_ids']==['claude-code','codex']
    assert not (Path(plan['home'])/'amap-controllers').exists()
    assert [x['path'] for x in common['submounts']]==['results','processed','ext','config.toml']
    cfg=tomllib.loads(plan['outputs'][plan['instances']['codex']['controller_config']])
    assert cfg['operator_kickoff_enabled'] and cfg['owner_domain']==plan['owner_domain']


def test_apply_refuses_preimage_or_dependency_drift(tmp_path):
    plan=fixture(tmp_path)
    path=Path(plan['home'])/'features'/'amap'/'router.json'
    path.write_text('{"state_dir":"changed"}')
    with pytest.raises(ValueError,match='host state changed'): pilot.apply_plan(plan)


def test_generated_toml_has_exact_tools_and_runtime_paths():
    config=tomllib.loads(pilot.codex_config('/home/user','c-33333333','fleet.example','fixture','/agent/work'))
    assert set(config['mcp_servers'])=={'inbox','delegation','inbox_submit'}
    assert config['mcp_servers']['delegation']['env']['INBOX_MESSAGE_DIR']=='/home/user/.amap/peer/messages'
    assert config['mcp_servers']['inbox_submit']['enabled_tools']==['submit','submit_result','peers']


def test_launcher_refuses_missing_host_guards(tmp_path,monkeypatch):
    plan=fixture(tmp_path)
    monkeypatch.setenv('AMAP_EXECUTION_ID','a'*32)
    monkeypatch.setenv('AMAP_DEPLOYMENT_ID',plan['instances']['codex']['deployment_id'])
    with mock.patch.object(pilot,'run',side_effect=AssertionError('no runtime call before guards')):
        with pytest.raises(FileNotFoundError): pilot.launch(plan,'codex')


def test_absent_binding_requires_stop_revocation(tmp_path,monkeypatch,capsys):
    plan=fixture(tmp_path)
    request={'version':1,'deployment_id':plan['instances']['codex']['deployment_id'],'execution_id':'a'*32}
    import io
    monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
    pilot.control(plan,'codex','inspect')
    assert json.loads(capsys.readouterr().out)['state']=='unknown'
    monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
    pilot.control(plan,'codex','stop')
    assert json.loads(capsys.readouterr().out)['state']=='stopped'
    assert json.loads(pilot.binding_path(plan['instances']['codex'],request['execution_id']).read_text())=={'revoked':True}


def test_service_keeps_supervisor_host_side(tmp_path):
    plan=fixture(tmp_path)
    with mock.patch.object(pilot.platform,'system',return_value='Darwin'):
        label,content=pilot.service(plan,'codex')
    import plistlib
    config=plistlib.loads(content)
    assert config['ProgramArguments'][-1]=='run'
    assert config['KeepAlive'] is True
    assert 'docker' not in config['ProgramArguments']


def test_apply_and_scoped_rollback_keep_router_state_and_evidence(tmp_path):
    plan=fixture(tmp_path)
    original={path:Path(path).read_bytes() for path,prior in plan['preimages'].items() if prior is not None}
    pilot.apply_plan(plan)
    pilot.apply_plan(plan)
    assert json.loads((tmp_path/'rollback'/'manifest.json').read_text())
    journal=Path(plan['instances']['codex']['state_dir'])/'retained-evidence'
    journal.write_text('keep')
    pilot.rollback(plan)
    for path,content in original.items(): assert Path(path).read_bytes()==content
    assert journal.read_text()=='keep'
    assert not (Path(plan['home'])/'features'/'amap-claude').exists()
    assert (tmp_path/'rollback'/'retained-amap-claude-feature'/'payload'/'relay').is_file()
    assert not (Path(plan['home'])/'amap-codex-pilot.json').exists()


def test_generated_runbook_uses_recorded_router_identity_and_real_paths(tmp_path):
    plan=fixture(tmp_path)
    plan['router_runtime']={'container_id':'a'*64,'name':'existing-router','image':'existing-image',
        'interval':'7','source':str(tmp_path/'router source'),'config':str(Path(plan['home'])/'features'/'amap'/'router.json')}
    with mock.patch.object(pilot.platform,'system',return_value='Darwin'):
        book=pilot.operator_runbook(plan)
    assert 'docker stop '+('a'*64) in book
    assert '--interval 7 --detach' in book
    assert 'launchctl bootstrap gui/'+str(os.getuid()) in book
    assert 'isolation-probe' in book and 'check-roundtrip --run-id R2' in book
    assert 'gh pr merge' not in book


def test_runtime_configuration_uses_read_only_payload_and_does_not_mutate(tmp_path):
    plan=fixture(tmp_path)
    with mock.patch.object(pilot,'current_container',return_value='a'*64), mock.patch.object(pilot,'container_identity',return_value={'home':'/home/agent','cwd':'/work/agent','slug':plan['instances']['codex']['slug']}):
        pilot.prepare_runtime_config(plan,'codex')
        pilot.prepare_runtime_config(plan,'codex')
    controller=tomllib.loads(plan['outputs'][plan['instances']['codex']['controller_config']])
    assert controller['cwd']=='/work/agent'
    trusted=tomllib.loads(plan['outputs'][controller['trusted_config_file']])
    assert trusted['model_reasoning_effort']=='low'
    assert set(trusted['mcp_servers'])=={'inbox','delegation','inbox_submit'}


def test_legacy_fleet_verify_cannot_pass_only_two_endpoint_checks(tmp_path, capsys):
    plan=fixture(tmp_path)
    pilot.apply_plan(plan)
    capsys.readouterr()
    with mock.patch.object(pilot,'current_container',side_effect=RuntimeError('runtime unavailable')):
        assert pilot.verify(plan,fleet=True)==1
    report=json.loads(capsys.readouterr().out)
    assert report['rollout_ready'] is False
    assert any(c['name']=='whole-fleet acceptance' and c['result']=='UNKNOWN' for c in report['checks'])


def test_apply_refuses_changed_pre_migration_container(tmp_path):
    plan=fixture(tmp_path)
    plan['instances']['claude']['pre_migration_container_id']='a'*64
    with mock.patch.object(pilot,'current_container',return_value='b'*64):
        with pytest.raises(ValueError,match='runtime identity changed'): pilot.apply_plan(plan)
    assert not (tmp_path/'rollback').exists()


def test_roundtrip_kickoff_ends_initiating_turn_and_queues_once(tmp_path):
    plan=fixture(tmp_path)
    with mock.patch.object(pilot,'current_container',return_value='a'*64), \
         mock.patch.object(pilot,'container_identity',return_value={'home':'/home/agent','cwd':'/work/agent','slug':plan['instances']['codex']['slug']}), \
         mock.patch.object(pilot,'run',return_value='queued') as run:
        pilot.roundtrip(plan,'codex-claude','R1')
        assert sum('-m' in call.args[0] for call in run.call_args_list)==1
        instructions=(tmp_path/'evidence'/'R1'/'kickoff.txt').read_text()
        assert 'finish this initiating turn' in instructions
        assert 'do not wait or poll' in instructions
        assert 'peer_message_id' in instructions
        with pytest.raises(ValueError,match='already prepared'): pilot.roundtrip(plan,'codex-claude','R1')
        assert sum('-m' in call.args[0] for call in run.call_args_list)==1
