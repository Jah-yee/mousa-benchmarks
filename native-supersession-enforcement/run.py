#!/usr/bin/env python3
"""Independent native CLI enforcement capture; Python 3.9+, standard library only."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
AUDIT_PREFIXES = ('policy_evaluation', 'policy_decision', 'source_trail')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()


def save(path, value):
    path.write_bytes(encoded(value))


def tuple_id(*fields):
    fields = [field.encode() if isinstance(field, str) else field for field in fields]
    return sha(b''.join(struct.pack('>Q', len(field)) + field for field in fields))


def identity(source, item, text):
    raw = text.encode()
    digest = hashlib.sha256(raw).digest()
    revision_suffix = digest.hex().encode().hex()
    observation = tuple_id('mousa.observation.v1', bytes.fromhex(source), 'item/' + item + '@' + revision_suffix)
    artifact = tuple_id('mousa.artifact.v1', bytes.fromhex(observation), 'body')
    representation = tuple_id('mousa.representation.v1', struct.pack('>Q', 1), 'artifact', bytes.fromhex(artifact),
                              'mousa.text.normalize_utf8', '1', hashlib.sha256(b'').digest(),
                              'text/plain; charset=utf-8', digest)
    segment = tuple_id('mousa.segment.v1', bytes.fromhex(representation), 'mousa.selector.text_byte_range.v1',
                      struct.pack('>Q', 0), struct.pack('>Q', len(raw)), digest)
    return dict(observation_id=observation, artifact_id=artifact, representation_id=representation, segment_id=segment)


def load_inputs(root=ROOT):
    protocol = json.loads((root / 'protocol.json').read_bytes())
    if protocol['schema'] != 'mousa.native_supersession_enforcement.v1':
        raise ValueError('unknown protocol')
    frozen = {}
    actual = {p.name for p in (root / 'inputs').iterdir() if p.is_file()}
    if actual != set(protocol['inputs']):
        raise ValueError('fixture membership differs')
    for name, digest in protocol['inputs'].items():
        data = (root / 'inputs' / name).read_bytes()
        if sha(data) != digest:
            raise ValueError('damaged frozen input: ' + name)
        frozen[name] = data
    source = tuple_id('mousa.source.v1', 'mousa-jsonl', protocol['source_external_id'])
    if source != protocol['source_id']:
        raise ValueError('source identity differs')
    for line in frozen['items.jsonl'].splitlines():
        item = json.loads(line)
        if identity(source, item['id'], item['text']) != protocol['pins'][item['id']]:
            raise ValueError('independently derived item identity differs')
    declaration = json.loads(frozen['declaration.json'])
    did = tuple_id(declaration['schema'], bytes.fromhex(source), declaration['predecessor_item_id'],
                   bytes.fromhex(declaration['predecessor_representation_id']), declaration['successor_item_id'],
                   bytes.fromhex(declaration['successor_representation_id']), declaration['author'], declaration['basis'])
    if did != declaration['id']:
        raise ValueError('declaration identity differs')
    previous = None
    for transition in ('initial', 'deactivation', 'reactivation'):
        event = json.loads(frozen['activation-' + transition + '.json'])
        selected = None if transition == 'deactivation' else did
        aid = tuple_id(event['schema'], bytes.fromhex(source), bytes.fromhex(previous) if previous else b'',
                       bytes.fromhex(selected) if selected else b'')
        if (event['id'], event['source_id'], event['expected_previous_activation_id'], event['declaration_id']) != (aid, source, previous, selected):
            raise ValueError('activation identity or chain differs')
        previous = aid
    limited_items = [json.loads(line) for line in frozen['over-limit.jsonl'].splitlines()]
    limited = json.loads(frozen['declaration-limit.json'])
    item = next(row for row in limited_items if row['id'] == protocol['successor'])
    derived = identity(source, item['id'], item['text'])
    if (derived['representation_id'], derived['segment_id']) != (limited['successor_representation_id'], protocol['limit_successor_segment_id']):
        raise ValueError('limited successor pin differs')
    limited_id = tuple_id(limited['schema'], bytes.fromhex(source), limited['predecessor_item_id'],
                          bytes.fromhex(limited['predecessor_representation_id']), limited['successor_item_id'],
                          bytes.fromhex(limited['successor_representation_id']), limited['author'], limited['basis'])
    event = json.loads(frozen['activation-limit.json'])
    if (limited['id'] != limited_id or event['declaration_id'] != limited_id or
            event['id'] != tuple_id(event['schema'], bytes.fromhex(source), b'', bytes.fromhex(limited_id))):
        raise ValueError('limited administration identity differs')
    return protocol, frozen


def sql_name(name):
    return '"' + name.replace('"', '""') + '"'


def sql_value(value):
    if isinstance(value, bytes):
        return ['blob', value.hex()]
    return [type(value).__name__, value]


def fingerprint(path):
    """Complete committed logical tables in one read snapshot, including WAL-visible rows."""
    if not path.exists():
        return None
    connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
    try:
        connection.execute('BEGIN')
        schema = list(connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"))
        tables = {}
        for kind, name, _, _ in schema:
            if kind != 'table':
                continue
            rows = [encoded([sql_value(v) for v in row]) for row in connection.execute('SELECT * FROM ' + sql_name(name))]
            rows.sort()
            tables[name] = {'rows': len(rows), 'sha256': sha(b''.join(rows))}
        return {'schema_sha256': sha(encoded(schema)), 'user_version': connection.execute('PRAGMA user_version').fetchone()[0],
                'tables': tables}
    finally:
        connection.close()


def immutable(fp):
    if fp is None:
        return None
    return {**fp, 'tables': {name: rows for name, rows in fp['tables'].items()
                            if not name.startswith(AUDIT_PREFIXES)}}


def stream(data):
    return {'bytes': len(data), 'sha256': sha(data), 'base64': base64.b64encode(data).decode(),
            'text': data.decode('utf-8', 'replace')}


def validate_pin(pin):
    for key in ('public_head', 'public_tree', 'executable_sha256', 'toolchain', 'build_command', 'build_environment', 'build_receipt'):
        if not pin.get(key):
            raise ValueError('missing published product/build pin field: ' + key)
    receipt = pin['build_receipt']
    if receipt['exit'] != 0:
        raise ValueError('supplied build did not succeed')
    if receipt['argv'] != pin['build_command']:
        raise ValueError('build command differs from receipt')
    for key in ('stdin', 'stdout', 'stderr'):
        if stream(base64.b64decode(receipt[key]['base64'], validate=True)) != receipt[key]:
            raise ValueError('damaged supplied build stream: ' + key)


def stable(query, history):
    """Stable selection, not fresh request/decision/trail identities or today's index flags."""
    q = {key: value for key, value in query.items()
         if key not in ('latency_micros', 'evaluated_at_usec', 'request_id', 'decision_id', 'trail_id')}
    h = {key: value for key, value in history.items()
         if key not in ('id', 'trail_id', 'request_id', 'decision_id')}
    h['candidates'] = [{key: value for key, value in row.items() if key != 'indexed_now'}
                       for row in h.get('candidates', [])]
    return {'query': q, 'history': h}


class Session:
    def __init__(self, protocol, frozen, binary=None, work=None, replay=None, forbidden=False):
        self.p, self.f = protocol, frozen
        self.binary, self.work = binary, work
        self.replay = replay
        self.forbidden = forbidden
        self.commands, self.assertions, self.selections = [], [], {}
        self.index = 0
        self.current_store = 'primary'
        self.ids = []
        self.item_texts = {}
        self.activation_state = {}

    def expect(self, ident, expected, observed):
        self.assertions.append({'id': ident, 'expected': expected, 'observed': observed,
                                'passed': type(expected) is type(observed) and expected == observed})

    def yes(self, ident, condition):
        self.expect(ident, True, bool(condition))

    def command(self, name, args, payload=b'', expected_exit=0, mode='write'):
        argv = ['<binary>', '-store', '<work>/' + self.current_store + '.sqlite', *args]
        if self.replay is not None:
            if self.index >= len(self.replay):
                raise ValueError('omitted command: ' + name)
            record = self.replay[self.index]
            self.index += 1
            if (record['step'], record['argv'], record['stdin']) != (name, argv, stream(payload)):
                raise ValueError('command/input differs: ' + name)
        else:
            path = self.work / (self.current_store + '.sqlite')
            before = fingerprint(path)
            actual = [str(self.binary), '-store', str(path), *args]
            actual = [token.replace('<work>', str(self.work)) for token in actual]
            result = subprocess.run(actual, input=payload, capture_output=True, cwd=self.work)
            injected = self.forbidden and mode == 'read'
            if injected:
                with sqlite3.connect(path) as connection:
                    connection.execute('CREATE TABLE forbidden_control(value TEXT)')
                self.forbidden = False
            after = fingerprint(path)
            if injected:
                # Preserve the measured violation, then restore the disposable fixture
                # so later startup failures cannot become the detector's failure cause.
                with sqlite3.connect(path) as connection:
                    connection.execute('DROP TABLE forbidden_control')
            record = {'step': name, 'argv': argv, 'stdin': stream(payload), 'exit': result.returncode,
                      'stdout': stream(result.stdout), 'stderr': stream(result.stderr),
                      'fingerprint_before': before, 'fingerprint_after': after, 'mode': mode}
            if injected:
                record['negative_control_sql'] = ['CREATE TABLE forbidden_control(value TEXT)', 'DROP TABLE forbidden_control']
        if record['mode'] != mode:
            raise ValueError('changed command mode: ' + name)
        self.commands.append(record)
        self.expect(name + ':exit', expected_exit, record['exit'])
        before, after = record['fingerprint_before'], record['fingerprint_after']
        if mode in ('read', 'reject'):
            self.expect(name + ':unchanged-all-tables', before, after)
        elif mode == 'query':
            self.expect(name + ':unchanged-administration-canonical-index', immutable(before), immutable(after))
            self.yes(name + ':audit-written', before != after)
        try:
            return json.loads(record['stdout']['text'])
        except (ValueError, TypeError):
            return None

    def sync(self, label, filename, source=None):
        source = source or self.p['source_external_id']
        report = self.command(label, ['sync', '--source', source], self.f[filename])
        current = self.item_texts.setdefault((self.current_store, source), {})
        for line in self.f[filename].splitlines():
            item = json.loads(line)
            if item.get('deleted'):
                current.pop(item['id'], None)
            else:
                current[item['id']] = item['text']
        return report

    def put(self, filename, reject=False):
        kind = 'declaration' if filename.startswith('declaration') else 'activation'
        step = ('reject-' if reject else 'put-') + filename
        report = self.command(step, ['supersession', kind, 'put'], self.f[filename],
                              1 if reject else 0, 'reject' if reject else 'write')
        if not reject:
            self.expect(step + ':canonical', json.loads(self.f[filename]), report)
            self.expect(step + ':canonical-bytes', sha(self.f[filename]), self.commands[-1]['stdout']['sha256'])
            if kind == 'activation':
                event = json.loads(self.f[filename])
                self.activation_state[(self.current_store, self.p['source_external_id'])] = event

    def query(self, name, text, policy, opt=True, budget=8192, source=None, suppressed=0, items=None, outcome='evidence'):
        args = ['query', '--source', source or self.p['source_external_id'], '--packing-policy', policy,
                '--budget-bytes', str(budget)]
        if opt:
            args.append('--supersession')
        args.append(text)
        q = self.command(name, args, mode='query') or {}
        self.expect(name + ':outcome', outcome, q.get('outcome'))
        self.expect(name + ':count-presence', opt, 'supersession_excluded' in q)
        if opt:
            self.expect(name + ':suppression-count', suppressed, q.get('supersession_excluded'))
        evidence = q.get('evidence', [])
        if items is not None:
            self.expect(name + ':items', sorted(items), sorted(hit['item'] for hit in evidence))
        self.expect(name + ':used-bytes', sum(len(hit['text'].encode()) for hit in evidence), q.get('used_bytes'))
        external = source or self.p['source_external_id']
        sid = tuple_id('mousa.source.v1', 'mousa-jsonl', external)
        for hit in evidence:
            expected_text = self.item_texts[(self.current_store, external)].get(hit['item'])
            self.expect(name + ':fixture-text-' + hit['item'], expected_text, hit['text'])
            if expected_text is not None:
                pin = identity(sid, hit['item'], expected_text)
                self.expect(name + ':representation-' + hit['item'], pin['representation_id'], hit['representation_id'])
                self.expect(name + ':segment-' + hit['item'], pin['segment_id'], hit['segment_id'])
                self.expect(name + ':digest-' + hit['item'], sha(expected_text.encode()), hit['content_sha256'])
        for key in ('packet_id', 'request_id', 'decision_id', 'trail_id'):
            value = q.get(key, '')
            self.yes(name + ':' + key + '-identity', isinstance(value, str) and len(value) == 64 and
                     all(c in '0123456789abcdef' for c in value))
        self.yes(name + ':fresh-request', q.get('request_id') not in self.ids)
        self.ids.append(q.get('request_id'))
        trail = self.command(name + '-trail', ['trail', '--source', source or self.p['source_external_id'],
                                             q.get('trail_id', '0' * 64)], mode='query') or {}
        history = trail.get('historical') or {}
        if outcome in ('policy_excluded', 'lifecycle_excluded'):
            self.expect(name + ':history-private', {}, history)
            self.expect(name + ':history-denied', 'deny', trail.get('authorization_outcome'))
            self.expect(name + ':denied-matched', 0, q.get('matched_candidates'))
            self.expect(name + ':denied-budget', 0, q.get('budget_omitted'))
            self.selections[name] = stable(q, {})
            return q, {}
        self.expect(name + ':v4', opt, history.get('schema') == 'mousa.source_trail.v4')
        for key in ('request_id', 'decision_id', 'packet_id', 'budget_bytes', 'used_bytes'):
            self.expect(name + ':history-' + key, q.get(key), history.get(key))
        selected = [row for row in history.get('candidates', []) if row.get('selected')]
        self.expect(name + ':selected-segments', sorted(hit['segment_id'] for hit in evidence),
                    sorted(row['segment_id'] for row in selected))
        candidates = history.get('candidates', [])
        self.expect(name + ':candidate-ranks', list(range(1, len(candidates) + 1)),
                    [row.get('rank') for row in candidates])
        fixture_rows = {identity(sid, item, text)['segment_id']: text
                        for item, text in self.item_texts[(self.current_store, external)].items()}
        by_segment = {row['segment_id']: row for row in candidates}
        for row in candidates:
            content = fixture_rows.get(row['segment_id'])
            self.yes(name + ':candidate-fixture-' + row['segment_id'], content is not None)
            if content is not None:
                self.expect(name + ':candidate-digest-' + row['segment_id'], sha(content.encode()), row.get('content_sha256'))
                self.expect(name + ':candidate-size-' + row['segment_id'], len(content.encode()), row.get('text_bytes'))
        for hit in evidence:
            row = by_segment.get(hit['segment_id'], {})
            self.expect(name + ':evidence-rank-' + hit['segment_id'], row.get('rank'), hit.get('rank'))
        self.expect(name + ':matched-count', len(candidates) + q.get('lifecycle_excluded', 0), q.get('matched_candidates'))
        withheld_ids = {row['segment_id'] for row in (history.get('supersession') or {}).get('dispositions', [])}
        omitted = [row for row in candidates if not row.get('selected') and row['segment_id'] not in withheld_ids]
        self.expect(name + ':budget-count', sum(not row.get('duplicate_of') for row in omitted), q.get('budget_omitted'))
        self.expect(name + ':duplicate-count-presence', policy == 'exact-v1', 'duplicate_omitted' in q)
        if policy == 'exact-v1':
            self.expect(name + ':duplicate-count', sum(bool(row.get('duplicate_of')) for row in omitted), q.get('duplicate_omitted'))
        if opt:
            member = history.get('supersession') or {}
            self.expect(name + ':consulted', outcome not in ('policy_excluded', 'lifecycle_excluded'), member.get('consulted'))
            event = self.activation_state.get((self.current_store, external))
            self.expect(name + ':activation-pin', event['id'] if event else None, member.get('activation_id'))
            self.expect(name + ':declaration-pin', event['declaration_id'] if event else None, member.get('declaration_id'))
            dispositions = member.get('dispositions', [])
            self.expect(name + ':dispositions-count', suppressed, len(dispositions))
            declaration = json.loads(self.f['declaration-limit.json' if self.current_store == 'limited' else 'declaration.json'])
            for row in dispositions:
                expected = {'selection': 'superseded', 'segment_id': self.p['pins'][self.p['predecessor']]['segment_id'],
                            'content_sha256': sha(b'oldterm predecessor evidence'), 'declaration_id': declaration['id'],
                            **{key: declaration[key] for key in ('predecessor_item_id', 'predecessor_representation_id',
                                                               'successor_item_id', 'successor_representation_id')}}
                self.expect(name + ':exact-pin-' + row['segment_id'], expected, row)
            withheld = {row['segment_id'] for row in dispositions}
            self.yes(name + ':withheld-not-released', not withheld.intersection(hit['segment_id'] for hit in evidence))
            for row in history.get('candidates', []):
                if row['segment_id'] in withheld:
                    self.yes(name + ':withheld-unselected-' + row['segment_id'], row.get('selected') is False)
                    self.expect(name + ':withheld-size-' + row['segment_id'],
                                len('oldterm predecessor evidence'.encode()), row.get('text_bytes'))
                    self.yes(name + ':withheld-not-packing-' + row['segment_id'], not row.get('omission'))
            self.yes(name + ':no-withheld-duplicate-reference',
                     not any(row.get('duplicate_of') in withheld for row in history.get('candidates', [])))
        self.selections[name] = stable(q, history)
        return q, history

    def run(self):
        p = self.p
        pred, succ, dup = p['predecessor'], p['successor'], p['duplicate']
        self.sync('sync-primary', 'items.jsonl')
        self.sync('sync-peer', 'items.jsonl', 'fixture/peer')
        old = {}
        for policy in p['policies']:
            default, _ = self.query(policy + '-default-no-history', 'oldterm', policy, False,
                                    items=[pred, dup] if policy == 'original' else None)
            opted, _ = self.query(policy + '-opt-no-history', 'oldterm', policy,
                                  items=[pred, dup] if policy == 'original' else None)
            self.expect(policy + ':same-no-history-packet', default.get('packet_id'), opted.get('packet_id'))
            self.yes(policy + ':different-no-history-trail', default.get('trail_id') != opted.get('trail_id'))
            old[policy] = default
            self.query(policy + '-default-budget', 'oldterm', policy, False,
                       budget=len('oldterm predecessor evidence'.encode()), items=[pred])
            self.query(policy + '-no-matches', 'absentword', policy, items=[], outcome='no_matches')
        self.put('declaration.json')
        self.put('activation-initial.json')
        did = json.loads(self.f['declaration.json'])['id']
        declaration = self.command('declaration-get', ['supersession', 'declaration', 'get', did], mode='read')
        self.expect('declaration-get:canonical', json.loads(self.f['declaration.json']), declaration)
        state = self.command('activation-state', ['supersession', 'activation', 'state', p['source_id']], mode='read')
        initial = json.loads(self.f['activation-initial.json'])
        self.expect('activation-state:value', {'source_id': p['source_id'], 'current_activation_id': initial['id'],
                                             'active_declaration_id': did}, state)
        event = self.command('activation-get', ['supersession', 'activation', 'get', initial['id']], mode='read')
        self.expect('activation-get:canonical', initial, event)
        historical = {}
        for policy in p['policies']:
            default, default_history = self.query(policy + '-default-active', 'oldterm', policy, False)
            self.expect(policy + ':default-compatible', stable(old[policy], {}), stable(default, {}))
            q, history = self.query(policy + '-active', 'oldterm', policy, suppressed=1, items=[dup])
            fields = ('segment_id', 'rank', 'content_sha256', 'text_bytes')
            self.expect(policy + ':suppression-preserves-candidate-metadata',
                        [{key: row[key] for key in fields} for row in default_history['candidates']],
                        [{key: row[key] for key in fields} for row in history['candidates']])
            historical[policy] = (q['trail_id'], history)
            self.query(policy + '-freed-budget', 'oldterm', policy,
                       budget=len('oldterm predecessor evidence'.encode()), suppressed=1, items=[dup])
            self.query(policy + '-mixed-budget', 'oldterm newterm', policy, budget=1, suppressed=1,
                       items=[], outcome='budget_omitted')
            self.query(policy + '-successor-matched', 'oldterm newterm', policy, suppressed=1, items=[dup, succ])
            self.query(policy + '-peer', 'oldterm', policy, source='fixture/peer',
                       items=[pred, dup] if policy == 'original' else None)
        self.put('activation-deactivation.json')
        for policy in p['policies']:
            q, _ = self.query(policy + '-deactivated', 'oldterm', policy)
            self.expect(policy + ':deactivated-packet', old[policy]['packet_id'], q.get('packet_id'))
            member = self.selections[policy + '-deactivated']['history'].get('supersession', {})
            self.expect(policy + ':deactivation-member', {'consulted': True,
                        'activation_id': json.loads(self.f['activation-deactivation.json'])['id'],
                        'declaration_id': None, 'dispositions': []}, member)
        self.put('activation-reactivation.json')
        self.put('activation-initial.json', reject=True)
        for policy in p['policies']:
            self.query(policy + '-reactivated', 'oldterm', policy, suppressed=1, items=[dup])
        self.sync('delete-duplicate', 'delete-duplicate.jsonl')
        for policy in p['policies']:
            self.query(policy + '-all-suppressed', 'oldterm', policy, suppressed=1, items=[], outcome='supersession_excluded')
        self.sync('delete-successor', 'delete-successor.jsonl')
        for policy in p['policies']:
            self.query(policy + '-successor-withdrawn', 'oldterm', policy, suppressed=1, items=[], outcome='supersession_excluded')
        self.sync('revise-successor', 'revise-successor.jsonl')
        for policy in p['policies']:
            self.query(policy + '-successor-revised', 'oldterm', policy, suppressed=1, items=[], outcome='supersession_excluded')
        self.sync('revise-predecessor', 'revise-predecessor.jsonl')
        for policy in p['policies']:
            self.query(policy + '-stale-pin', 'oldterm', policy, items=[pred])
            trail_id, original = historical[policy]
            report = self.command(policy + '-historical-after-revisions', ['trail', '--source', p['source_external_id'], trail_id], mode='query') or {}
            current = report.get('historical') or {}
            self.expect(policy + ':historical-selection-unchanged', stable({}, original), stable({}, current))
            first, _ = self.query(policy + '-restart-first', 'oldterm', policy, items=[pred])
            second, _ = self.query(policy + '-restart-second', 'oldterm', policy, items=[pred])
            self.expect(policy + ':restart-packet', first.get('packet_id'), second.get('packet_id'))
        self.command('deny-source', ['access', '--source', p['source_external_id'], 'deny'])
        denied = {}
        for policy in p['policies']:
            denied[policy], _ = self.query(policy + '-deny', 'oldterm', policy, items=[], outcome='policy_excluded')
        self.command('allow-source', ['access', '--source', p['source_external_id'], 'allow'])
        for policy in p['policies']:
            report = self.command(policy + '-denied-history-after-allow',
                                  ['trail', '--source', p['source_external_id'], denied[policy]['trail_id']], mode='query') or {}
            history = report.get('historical') or {}
            self.expect(policy + ':denied-v4', 'mousa.source_trail.v4', history.get('schema'))
            self.expect(policy + ':denied-unconsulted', {'consulted': False, 'activation_id': None,
                        'declaration_id': None, 'dispositions': []}, history.get('supersession'))
            self.selections[policy + '-denied-history-after-allow'] = stable({}, history)
        self.command('withdraw-source', ['withdraw', '--source', p['source_external_id']])
        for policy in p['policies']:
            self.query(policy + '-withdrawn-source', 'oldterm', policy, items=[], outcome='lifecycle_excluded')
        for name, args in [('invalid-boolean', ['query', '--source', p['source_external_id'], '--supersession=maybe', 'oldterm']),
                           ('directory-opt-in', ['query', '--supersession', '.', 'oldterm']),
                           ('association-opt-in', ['query', '--source', p['source_external_id'], '--supersession', '--associations', '<work>/associations.jsonl', 'oldterm'])]:
            self.command(name, args, expected_exit=2, mode='reject')
        self.command('unknown-declaration', ['supersession', 'declaration', 'get', 'f' * 64], expected_exit=1, mode='read')
        self.command('unknown-source-query', ['query', '--source', 'fixture/genuinely-unknown', '--supersession', 'oldterm'],
                     expected_exit=1, mode='reject')
        self.expect('unknown-source:no-stdout', '', self.commands[-1]['stdout']['text'])
        self.yes('unknown-source:legacy-integrity', 'integrity' in self.commands[-1]['stderr']['text'])
        self.current_store = 'limited'
        self.sync('limited-sync', 'over-limit.jsonl')
        self.put('declaration-limit.json')
        self.put('activation-limit.json')
        for policy in p['policies']:
            q, _ = self.query(policy + '-over-limit-successor', 'oldterm limitword', policy, suppressed=1)
            self.expect(policy + ':limit', 100, q.get('candidate_limit'))
            self.yes(policy + ':successor-outside-limit', not any(hit['item'] == succ for hit in q.get('evidence', [])))
            candidates = self.selections[policy + '-over-limit-successor']['history'].get('candidates', [])
            self.yes(policy + ':pinned-successor-not-considered',
                     not any(row['segment_id'] == self.p['limit_successor_segment_id'] for row in candidates))
        self.current_store = 'primary'
        # Independent fixture damage, before process startup. This is not a live transaction seam.
        if self.replay is None:
            with sqlite3.connect(self.work / 'primary.sqlite') as connection:
                connection.execute('DELETE FROM supersession_activation_state')
        for policy in p['policies']:
            self.command('damaged-store-startup-refusal-' + policy,
                         ['query', '--source', p['source_external_id'], '--packing-policy', policy, '--supersession', 'oldterm'],
                         expected_exit=1, mode='reject')
            self.expect('damaged-store:' + policy + ':no-stdout', '', self.commands[-1]['stdout']['text'])
            self.yes('damaged-store:' + policy + ':integrity', 'integrity' in self.commands[-1]['stderr']['text'])
        if self.replay is not None and self.index != len(self.replay):
            raise ValueError('unexpected extra invocation')
        if len({a['id'] for a in self.assertions}) != len(self.assertions):
            raise ValueError('duplicate assertion IDs')
        return self


def make_manifest(directory):
    files = {}
    for path in sorted(directory.rglob('*')):
        if path.is_file() and path.name != 'manifest.json':
            data = path.read_bytes()
            files[str(path.relative_to(directory))] = {'bytes': len(data), 'sha256': sha(data)}
    save(directory / 'manifest.json', {'schema': 'mousa.run_manifest.v1', 'files': files})


def verify(directory, require_pass=True):
    manifest = json.loads((directory / 'manifest.json').read_bytes())['files']
    actual = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file() and p != directory / 'manifest.json'}
    if set(manifest) != actual:
        raise ValueError('archive membership differs')
    required = {'run.py', 'protocol.json', 'observed.json', 'assertions.json', 'product-pin.json'}
    if not required.issubset(actual):
        raise ValueError('missing required archive member')
    for name, entry in manifest.items():
        data = (directory / name).read_bytes()
        if entry != {'bytes': len(data), 'sha256': sha(data)}:
            raise ValueError('archive digest differs: ' + name)
    for name in ('run.py', 'protocol.json'):
        if (directory / name).read_bytes() != (ROOT / name).read_bytes():
            raise ValueError('capture does not match this committed runner/protocol: ' + name)
    protocol, frozen = load_inputs(directory)
    observed = json.loads((directory / 'observed.json').read_bytes())
    if observed['runner_sha256'] != sha((ROOT / 'run.py').read_bytes()) or observed['protocol_sha256'] != sha((ROOT / 'protocol.json').read_bytes()):
        raise ValueError('observation provenance hashes differ')
    pin = json.loads((directory / 'product-pin.json').read_bytes())
    validate_pin(pin)
    if pin != observed['product_pin']:
        raise ValueError('pin receipt differs')
    provenance = observed['provenance_commands']
    expected_argv = [['git', '-C', root, *command] for root in ('<product>', '<companion>') for command in
                     (['rev-parse', 'HEAD'], ['rev-parse', 'HEAD^{tree}'], ['status', '--porcelain'])]
    if [c['argv'] for c in provenance] != expected_argv or any(c['exit'] != 0 for c in provenance):
        raise ValueError('omitted or changed provenance command')
    expected_stdout = [pin['public_head'], pin['public_tree'], '', observed['companion_execution']['head'],
                       observed['companion_execution']['tree'], '']
    if [c['stdout']['text'].strip() for c in provenance] != expected_stdout:
        raise ValueError('source/companion execution pin differs')
    for command in observed['commands'] + observed['provenance_commands']:
        for key in ('stdin', 'stdout', 'stderr'):
            data = base64.b64decode(command[key]['base64'], validate=True)
            if stream(data) != command[key]:
                raise ValueError('damaged invocation stream')
    regenerated = Session(protocol, frozen, replay=observed['commands']).run()
    expected_path = directory / 'expectations.json'
    if observed.get('expectations_sha256') is not None:
        if not expected_path.is_file():
            raise ValueError('missing frozen expectations')
        expected = json.loads(expected_path.read_bytes())
        if (sha(encoded(expected)) != observed['expectations_sha256'] or expected['product_pin'] != pin
                or expected['protocol_sha256'] != observed['protocol_sha256']):
            raise ValueError('wrong frozen expectations')
        regenerated.expect('frozen-pilot-selections', expected['selections'], regenerated.selections)
    elif expected_path.exists():
        raise ValueError('unexpected frozen expectations')
    assertions = json.loads((directory / 'assertions.json').read_bytes())
    if assertions != regenerated.assertions or observed['selections'] != regenerated.selections:
        raise ValueError('omitted or tampered assertion/selection')
    if require_pass and not all(a['passed'] for a in assertions):
        raise ValueError('false assertion: ' + ', '.join(a['id'] for a in assertions if not a['passed']))
    return observed, regenerated


def provenance_command(argv):
    result = subprocess.run(argv, capture_output=True)
    return {'argv': argv, 'stdin': stream(b''), 'exit': result.returncode,
            'stdout': stream(result.stdout), 'stderr': stream(result.stderr)}


def capture(args):
    protocol, frozen = load_inputs()
    pin = json.loads(args.pin.read_bytes())
    validate_pin(pin)
    binary = args.binary.resolve()
    if sha(binary.read_bytes()) != pin['executable_sha256']:
        raise ValueError('executable differs from published build receipt')
    commands = [provenance_command(['git', '-C', str(args.source), *command]) for command in
                (['rev-parse', 'HEAD'], ['rev-parse', 'HEAD^{tree}'], ['status', '--porcelain'])]
    if any(c['exit'] != 0 for c in commands) or [c['stdout']['text'].strip() for c in commands] != [pin['public_head'], pin['public_tree'], '']:
        raise ValueError('source checkout not clean at published product pin')
    companion_commands = [provenance_command(['git', '-C', str(ROOT.parent), *command]) for command in
                          (['rev-parse', 'HEAD'], ['rev-parse', 'HEAD^{tree}'], ['status', '--porcelain'])]
    if any(c['exit'] != 0 for c in companion_commands) or companion_commands[-1]['stdout']['text'].strip():
        raise ValueError('companion execution tree must be committed and clean')
    companion = {'head': companion_commands[0]['stdout']['text'].strip(),
                 'tree': companion_commands[1]['stdout']['text'].strip()}
    for command in commands:
        command['argv'][2] = '<product>'
    for command in companion_commands:
        command['argv'][2] = '<companion>'
    commands.extend(companion_commands)
    if args.output.exists():
        raise ValueError('output already exists')
    if args.expectations:
        expected = json.loads(args.expectations.read_bytes())
        if expected['product_pin'] != pin or expected['protocol_sha256'] != sha((ROOT / 'protocol.json').read_bytes()):
            raise ValueError('frozen pilot expectations do not match product/protocol')
    else:
        expected = None
    args.output.mkdir(parents=True)
    for name in ('run.py', 'protocol.json'):
        shutil.copyfile(ROOT / name, args.output / name)
    shutil.copytree(ROOT / 'inputs', args.output / 'inputs')
    save(args.output / 'product-pin.json', pin)
    with tempfile.TemporaryDirectory(prefix='mousa-enforcement-') as temp:
        work = Path(temp)
        (work / 'associations.jsonl').write_text('[]\n')
        session = Session(protocol, frozen, binary, work, forbidden=args.forbidden_write)
        try:
            session.run()
        except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as error:
            # Keep all completed subprocess receipts even when a malformed report interrupts the schedule.
            session.expect('runner-completed-schedule', 'complete', type(error).__name__ + ': ' + str(error))
    if expected is not None:
        save(args.output / 'expectations.json', expected)
        # Expected identities are from an actual verified pilot, never manufactured.
        session.expect('frozen-pilot-selections', expected['selections'], session.selections)
    observed = {'schema': protocol['schema'], 'captured_at_utc': datetime.now(timezone.utc).isoformat(),
                'runner_sha256': sha((ROOT / 'run.py').read_bytes()), 'protocol_sha256': sha((ROOT / 'protocol.json').read_bytes()),
                'product_pin': pin, 'provenance_commands': commands, 'commands': session.commands,
                'companion_execution': companion,
                'selections': session.selections, 'python_version': sys.version, 'sqlite_version': sqlite3.sqlite_version,
                'expectations_sha256': sha(encoded(expected)) if expected else None}
    save(args.output / 'observed.json', observed)
    save(args.output / 'assertions.json', session.assertions)
    make_manifest(args.output)
    return 0 if all(a['passed'] for a in session.assertions) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    for mode in ('pilot', 'capture', 'forbidden-write'):
        sub = modes.add_parser(mode)
        sub.add_argument('--binary', type=Path, required=True)
        sub.add_argument('--source', type=Path, required=True)
        sub.add_argument('--pin', type=Path, required=True)
        sub.add_argument('--output', type=Path, required=True)
        sub.add_argument('--expectations', type=Path, required=mode == 'capture')
        sub.set_defaults(forbidden_write=mode == 'forbidden-write')
    sub = modes.add_parser('verify')
    sub.add_argument('directory', type=Path)
    sub = modes.add_parser('manifest')
    sub.add_argument('directory', type=Path)
    sub = modes.add_parser('freeze')
    sub.add_argument('pilot', type=Path)
    sub.add_argument('--output', type=Path, required=True)
    sub = modes.add_parser('negative-controls')
    sub.add_argument('capture', type=Path)
    sub.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode in ('pilot', 'capture', 'forbidden-write'):
            return capture(args)
        if args.mode == 'verify':
            verify(args.directory)
            print('Verified complete native assertions and archive members')
        elif args.mode == 'manifest':
            make_manifest(args.directory)
        elif args.mode == 'freeze':
            observed, session = verify(args.pilot)
            if args.output.exists():
                raise ValueError('expectation output already exists')
            save(args.output, {'schema': 'mousa.native_supersession_expectations.v1', 'product_pin': observed['product_pin'],
                               'protocol_sha256': observed['protocol_sha256'], 'pilot_observed_sha256': sha((args.pilot / 'observed.json').read_bytes()),
                               'selections': session.selections})
        else:
            negative_controls(args)
        return 0
    except (ValueError, KeyError, OSError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        return 2


def negative_controls(args):
    verify(args.capture)
    if args.output.exists():
        raise ValueError('negative-control output exists')
    args.output.mkdir(parents=True)
    results = []
    protocol, frozen = load_inputs()
    false_session = Session(protocol, frozen)
    false_session.yes('negative-actual-false', False)
    actual_false = false_session.assertions[0]
    results.append({'control': 'actual-false-condition', 'assertion': actual_false,
                    'rejected': actual_false['observed'] is False and actual_false['passed'] is False})
    for kind in ('damaged-input', 'wrong-expectation', 'false-boolean', 'omitted-assertion', 'failed-build', 'damaged-build-stream', 'forbidden-write'):
        directory = args.output / kind
        shutil.copytree(args.capture, directory)
        if kind == 'damaged-input':
            path = directory / 'inputs' / 'items.jsonl'
            path.write_bytes(path.read_bytes() + b'\n')
        elif kind == 'wrong-expectation' and (directory / 'expectations.json').is_file():
            path = directory / 'expectations.json'
            expected = json.loads(path.read_bytes())
            selection = next(iter(expected['selections'].values()))
            selection['query']['packet_id'] = 'f' * 64
            save(path, expected)
            observation_path = directory / 'observed.json'
            observation = json.loads(observation_path.read_bytes())
            observation['expectations_sha256'] = sha(encoded(expected))
            save(observation_path, observation)
        elif kind in ('wrong-expectation', 'false-boolean', 'omitted-assertion'):
            path = directory / 'assertions.json'
            assertions = json.loads(path.read_bytes())
            if kind == 'wrong-expectation':
                assertions[0]['expected'] = 999
            elif kind == 'omitted-assertion':
                assertions.pop()
            else:
                assertion = next(a for a in assertions if a['expected'] is True and a['observed'] is True)
                assertion['observed'] = False
                assertion['passed'] = True
            save(path, assertions)
        elif kind in ('failed-build', 'damaged-build-stream'):
            pin_path = directory / 'product-pin.json'
            pin = json.loads(pin_path.read_bytes())
            if kind == 'failed-build':
                pin['build_receipt']['exit'] = 1
            else:
                pin['build_receipt']['stdout']['sha256'] = 'f' * 64
            save(pin_path, pin)
            observation_path = directory / 'observed.json'
            observation = json.loads(observation_path.read_bytes())
            observation['product_pin'] = pin
            save(observation_path, observation)
        else:
            path = directory / 'observed.json'
            observed = json.loads(path.read_bytes())
            command = next(c for c in observed['commands'] if c['mode'] == 'read')
            command['fingerprint_after']['tables']['forbidden_control'] = {'rows': 1, 'sha256': sha(b'forbidden')}
            save(path, observed)
        # Recompute the manifest: assertion and protocol validation must detect the fault,
        # rather than relying only on a stale file checksum.
        make_manifest(directory)
        try:
            verify(directory)
        except ValueError as error:
            results.append({'control': kind, 'rejected': True, 'error': str(error)})
        else:
            results.append({'control': kind, 'rejected': False})
    save(args.output / 'negative-controls.json', results)
    if not all(row['rejected'] for row in results):
        raise ValueError('negative control accepted')


if __name__ == '__main__':
    sys.exit(main())
