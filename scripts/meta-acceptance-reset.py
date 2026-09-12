#!/usr/bin/env python3
"""Fresh isolated acceptance Box; retain the preceding deployment as evidence.

Run on the Proxmox guest from a committed source archive. This deliberately does
not reset ordinary Box installations, touch clients, remove volumes or migrate
partially transferred Spaces. Repeating requires a new acceptance project name.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


PROJECT = re.compile(r"facets-meta-acceptance-[0-9]{8}(?:-[a-z0-9]+)*")


def validated_paths(root, source, previous_source, previous_configuration, project, previous_project):
    root, source, previous_source, previous_configuration = map(Path, (
        root, source, previous_source, previous_configuration))
    if (not root.is_absolute() or root.parent.parent != Path('/home')
            or not PROJECT.fullmatch(root.name)
            or not PROJECT.fullmatch(project) or not PROJECT.fullmatch(previous_project)
            or project == previous_project):
        raise ValueError('Require distinct isolated acceptance projects under a dedicated /home/user root')
    for path in (source, previous_source, previous_configuration):
        if path.parent != root or path.resolve() != path or not path.is_dir():
            raise ValueError('Source/configuration must be existing direct children of the acceptance root')
    return root, source, previous_source, previous_configuration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'previous-source', 'previous-configuration', 'project', 'previous-project', 'address', 'revision', 'tree', 'prepare-executable'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--confirm', action='store_true')
    args = parser.parse_args()
    source = Path(__file__).resolve().parent.parent
    root, source, previous_source, previous_configuration = validated_paths(
        args.root, source, args.previous_source, args.previous_configuration, args.project, args.previous_project)
    if not args.confirm or not all(re.fullmatch('[a-f0-9]{40}', value) for value in (args.revision, args.tree)):
        parser.error('Require --confirm and exact committed revision/tree')
    prepare = Path(args.prepare_executable)
    if prepare.parent != root or prepare.resolve() != prepare or not prepare.is_file() or prepare.name != 'prepare-' + args.revision:
        raise ValueError('Require the preparation executable built from this revision in the acceptance root')
    config = root / ('configuration-' + args.project)
    evidence = root / ('preserved-before-' + args.project)
    if config.exists() or evidence.exists():
        raise ValueError('Fresh configuration/evidence already exists; refusing to overwrite')
    env = dict(os.environ, DOCKER_CONFIG=str(root / 'docker-config'), COMPOSE_BAKE='false',
               FACETS_SERVER_SOURCE_REVISION=args.revision, FACETS_SERVER_SOURCE_TREE=args.tree)

    def run(command, **kwargs):
        return subprocess.run(command, env=env, check=True, **kwargs)

    def compose(directory, configuration, project):
        return ['docker', 'compose', '--project-directory', str(directory), '--env-file', str(configuration / '.env'),
                '-f', str(directory / 'compose.yaml'), '-p', project]

    old = compose(previous_source, previous_configuration, args.previous_project)
    new = compose(source, config, args.project)
    # Inspect actual project labels before stopping anything. Credentials are
    # deliberately never rendered through `compose config` or docker inspect.
    ids = run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + args.previous_project],
              capture_output=True, text=True).stdout.split()
    if not ids:
        raise ValueError('Previous isolated project has no containers to preserve')
    for identity in ids:
        labels = json.loads(run(['docker', 'inspect', '-f', '{{json .Config.Labels}}', identity],
                               capture_output=True, text=True).stdout)
        if labels.get('com.docker.compose.project.config_files') != str(previous_source / 'compose.yaml'):
            raise ValueError('Previous container source does not match the explicit acceptance source')
    if run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + args.project],
           capture_output=True, text=True).stdout.strip():
        raise ValueError('New project is already in use')
    if run(['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + args.project],
           capture_output=True, text=True).stdout.strip():
        raise ValueError('New project already owns durable state')
    os.umask(0o077)
    evidence.mkdir(mode=0o700)
    with (evidence / 'client-baseline-server.log').open('wb') as output:
        run(old + ['logs', '--no-color'], stdout=output, stderr=subprocess.STDOUT)
    # Build the exact fresh service before any interruption of the old one.
    run([str(prepare), '--directory', str(config), '--address', args.address], cwd=source)
    run(new + ['build', 'server', 'controller', 'discovery'], cwd=source)
    run(old + ['stop', 'controller', 'discovery', 'ingress', 'server'])
    for service, user, name in [('postgres', 'facets_device_sync', 'sync.pg_dump'),
                                ('box-postgres', 'facets_box_controller', 'controller.pg_dump')]:
        with (evidence / name).open('wb') as output:
            run(old + ['exec', '-T', service, 'pg_dump', '-U', user, '-d', user, '-Fc'], stdout=output)
    run(old + ['stop'])
    volumes = run(['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + args.previous_project],
                  capture_output=True, text=True).stdout.split()
    if len(volumes) != 4:
        raise ValueError('Expected four preserved acceptance volumes; no volumes removed')
    record = {'previousProject': args.previous_project, 'preservedVolumes': volumes,
              'preservedConfiguration': str(previous_configuration), 'revision': args.revision, 'tree': args.tree,
              'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence.iterdir() if p.is_file()}}
    (evidence / 'record.json').write_text(json.dumps(record, indent=2) + '\n')
    # Runtime UID owns only this newly generated authority directory.
    run(['sudo', '-n', 'chown', '-R', '65532:65532', str(config / 'keys'), str(config / 'policy'), str(config / 'state')])
    run(new + ['up', '-d', '--wait', '--no-build', 'postgres', 'box-postgres', 'server'])
    with (config / 'activation.txt').open('wb') as output:
        run(new + ['run', '--rm', '--no-deps', 'controller', 'initialize'], stdout=output)
    run(new + ['up', '-d', '--wait', '--no-build'])
    print('Fresh acceptance Box started. Previous databases, blobs, authority and logs retained at ' + str(evidence))
    print('Activation is private in the fresh configuration directory; no client has been enrolled.')


if __name__ == '__main__':
    main()
