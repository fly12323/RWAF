"""Compare complete, identical corpora; reject partial runs and engine errors."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def load(directory):
    directory = Path(directory)
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    corpus = json.loads((directory / 'corpus.json').read_text(encoding='utf-8'))
    outcomes = [json.loads(line) for line in (directory / 'outcomes.jsonl').read_text(encoding='utf-8').splitlines()]
    keys = {(pl, threshold) for pl in range(1, 5) for threshold in (5, 10, 15)}
    assert len(summary['results']) == 12
    assert {(r['pl'], r['threshold']) for r in summary['results']} == keys
    indexed = {(o['pl'], o['threshold'], o['id']): o for o in outcomes}
    assert len(indexed) == len(outcomes) == len(corpus) * 12, 'Incomplete/duplicate outcomes'
    assert not any(o.get('error') for o in outcomes), 'Engine errors require separate review'
    assert len({s['id'] for s in corpus}) == len(corpus)
    for row in summary['results']:
        selected = [o for o in outcomes if (o['pl'], o['threshold']) == (row['pl'], row['threshold'])]
        for group, counts in row['groups'].items():
            members = [o for o in selected if group in (o['dataset'], o['dataset'] + '/' + o['category'])]
            assert len(members) == counts['n']
            assert sum(o['blocked'] for o in members) == counts['blocked']
            assert sum(o['expected_matched'] for o in members) == counts['expected_matched']
    return summary, corpus, indexed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before'); parser.add_argument('after'); parser.add_argument('--out', required=True)
    parser.add_argument('--details', help='Optional file for every changed verdict')
    args = parser.parse_args()
    before, corpus, old = load(args.before)
    after, corpus_after, new = load(args.after)
    assert corpus == corpus_after, 'Corpus changed between runs'
    assert before['corpus_sha256'] == after['corpus_sha256']
    assert before['rules_sha256'] == after['rules_sha256'], 'CRS rule text changed'
    assert old.keys() == new.keys()
    rows, changed = [], []
    for previous, current in zip(before['results'], after['results']):
        assert (previous['pl'], previous['threshold']) == (current['pl'], current['threshold'])
        row = {'pl': previous['pl'], 'threshold': previous['threshold'], 'groups': {}}
        for group in ('benign-basic', 'benign-complex', 'attack-probe', 'context-probe', 'crs-positive'):
            a, b = previous['groups'][group], current['groups'][group]
            row['groups'][group] = {'n': a['n'], 'blocked_before': a['blocked'], 'blocked_after': b['blocked'],
                'unblocked_before': a['n'] - a['blocked'], 'unblocked_after': b['n'] - b['blocked'],
                'expected_matches_before': a['expected_matched'], 'expected_matches_after': b['expected_matched']}
        rows.append(row)
    for key, value in old.items():
        updated = new[key]
        if (value['blocked'], value['expected_matched']) != (updated['blocked'], updated['expected_matched']):
            changed.append({'pl': key[0], 'threshold': key[1], 'id': key[2], 'dataset': value['dataset'],
                'blocked_before': value['blocked'], 'blocked_after': updated['blocked'],
                'expected_match_before': value['expected_matched'], 'expected_match_after': updated['expected_matched']})
    lost = [c for c in changed if c['expected_match_before'] and not c['expected_match_after']]
    transports = Counter(c['id'].rsplit('/', 1)[-1] for c in changed if c['dataset'] != 'crs-positive')
    report = {'corpus_sha256': before['corpus_sha256'], 'rules_sha256': before['rules_sha256'],
        'transactions_per_run': len(old), 'errors_before': 0, 'errors_after': 0,
        'changed_curated_transports': dict(transports), 'lost_expected_rule_matches': lost, 'results': rows, 'changed_verdict_count': len(changed)}
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    if args.details:
        Path(args.details).write_text(json.dumps(changed, ensure_ascii=False, indent=2), encoding='utf-8')
    for row in rows:
        if row['threshold'] == 5:
            print('PL', row['pl'], json.dumps(row['groups'], ensure_ascii=False))
    print('Lost expected rule matches:', len(lost), 'curated changed transports:', dict(transports))


if __name__ == '__main__':
    main()
