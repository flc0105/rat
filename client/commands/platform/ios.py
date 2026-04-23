import json
import os
import platform
import shutil
import sys
import time



from client.commands.argument_command_registry import argument_command, ArgumentCommandSpec, ArgumentOptionSpec
from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.common import CommonCommands
from client.commands.interrupts import timeout, cancel_policy, interruptible
from client.config.config import UPLOAD_BASE_URL
from client.config.runtime_config import HTTP_TRANSFER_MODE
from client.utils.ios_util import _safe_call, get_ios_process_info, get_ios_device_info, get_ios_bundle_info, \
    get_ios_username
from core.platform.platform_identity import detect_platform_alias
from core.utils.client_util import get_executable_path, upload_file_via_http
from core.utils.command_output import StructuredCommandResult
from core.utils.decorator import desc
from core.utils.formatting import get_size
from core.utils.logger import logger


if detect_platform_alias() == 'ios':
    from objc_util import ObjCClass, ns, ObjCInstance

upload_url = UPLOAD_BASE_URL.rstrip('/') + '/api/files/upload'










class iOSCommands(CommonCommands):
    """iOS / Pythonista 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)

    # def upload_file_via_http(
    #         self,
    #         file_source,
    #         category=None,
    #         filename=None
    # ):
    #     import os
    #     import requests
    #
    #     form_data = {
    #         'artifact_type': 'files',
    #         'category': (category or '').strip() or 'default',
    #         'client_id': getattr(self.socket, 'client_id', '') or '',
    #     }
    #
    #     close_after = False
    #
    #     if isinstance(file_source, str):
    #         file_obj = open(file_source, 'rb')
    #         close_after = True
    #         upload_name = filename or os.path.basename(file_source)
    #     else:
    #         file_obj = file_source
    #         upload_name = filename or getattr(file_obj, 'name', None) or 'upload.bin'
    #
    #     try:
    #         # 尽量从头开始读
    #         try:
    #             file_obj.seek(0)
    #         except Exception:
    #             pass
    #
    #         files = {
    #             'file': (upload_name, file_obj)
    #         }
    #
    #         response = requests.post(
    #             upload_url,
    #             files=files,
    #             data=form_data,
    #             timeout=30,
    #         )
    #
    #         return response
    #
    #     finally:
    #         if close_after:
    #             try:
    #                 file_obj.close()
    #             except Exception:
    #                 pass

    # ------------------ 基础 shell ------------------ #

    @desc('List directory contents', group='shell')
    @interruptible()
    def ls(self, path='.'):
        try:
            target = os.path.expanduser((path or '.').strip())
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'

            entries = []
            for name in os.listdir(target):
                full = os.path.join(target, name)
                is_dir = os.path.isdir(full)
                is_link = os.path.islink(full)
                display_name = f'{name}/' if is_dir else (f'{name}@' if is_link else name)
                entries.append((0 if is_dir else 1, name.lower(), display_name))

            entries.sort(key=lambda x: (x[0], x[1]))

            return 1, '\n'.join(item[2] for item in entries)

        except Exception as e:
            return 0, f'ls failed: {e}'

    @desc('Show current username', group='shell')
    @interruptible()
    def whoami(self):
        try:
            return 1, str(get_ios_username())
        except Exception as e:
            return 0, f'whoami failed: {e}'

    @desc('Create empty file', group='shell')
    @interruptible()
    def touch(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: touch <path>'

            parent = os.path.dirname(target)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

            with open(target, 'a', encoding='utf-8'):
                os.utime(target, None)

            return 1, f'File touched: {target}'

        except Exception as e:
            return 0, f'touch failed: {e}'

    @desc('Create directory', group='shell')
    @interruptible()
    def mkdir(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: mkdir <path>'

            os.makedirs(target, exist_ok=True)
            return 1, f'Directory created: {target}'

        except Exception as e:
            return 0, f'mkdir failed: {e}'

    @desc('Remove file', group='shell')
    @interruptible()
    def rm(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: rm <file>'

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if os.path.isdir(target):
                return 0, f'Is a directory: {target}'

            os.remove(target)
            return 1, f'File removed: {target}'

        except Exception as e:
            return 0, f'rm failed: {e}'

    @desc('Remove directory recursively', group='shell')
    @interruptible()
    def rmdir(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: rmdir <dir>'

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'

            shutil.rmtree(target)
            return 1, f'Directory removed: {target}'

        except Exception as e:
            return 0, f'rmdir failed: {e}'

    @desc('Read text file', group='shell')
    @interruptible()
    def cat(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: cat <file>'

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isfile(target):
                return 0, f'Not a file: {target}'

            with open(target, 'r', encoding='utf-8', errors='replace') as f:
                return 1, f.read()

        except Exception as e:
            return 0, f'cat failed: {e}'

    # ------------------ 系统信息 ------------------ #

    @desc('Get system information', group='platform')
    @interruptible()
    @timeout(20)
    @cancel_policy(True)
    def getinfo(self):
        """
        获取 iOS / Pythonista 信息
        返回扁平 JSON
        """
        try:
            from pathlib import Path
            import os
            device = get_ios_device_info()
            proc = get_ios_process_info()
            bundle = get_ios_bundle_info()

            info = {
                'device_name': device.get('device_name'),
                'device_model': device.get('device_model'),
                'device_type': device.get('device_type'),
                'machine_name': device.get('machine_name') or platform.machine(),
                'hostname': device.get('hostname'),
                'system': device.get('system'),
                'system_version': device.get('system_version'),
                'identifier_for_vendor': device.get('identifier_for_vendor'),
                'platform': _safe_call(platform.platform),
                'kernel_release': _safe_call(platform.release),
                'kernel_version': _safe_call(platform.version),
                'python_compiler': _safe_call(platform.python_compiler),
                'python_version': sys.version,
                'python_version_short': _safe_call(platform.python_version),
                'process_name': proc.get('process_name'),
                'process_id': proc.get('process_id'),
                'username': proc.get('username'),
                'executable_path': get_executable_path(),
                'processor_count': proc.get('processor_count'),
                'physical_memory': proc.get('physical_memory'),
                'system_boot_time': proc.get('system_boot_time'),
                'system_uptime': proc.get('system_uptime'),
                'os_version_string': proc.get('operating_system_version_string'),
                'low_power_mode_enabled': proc.get('low_power_mode_enabled'),
                'bundle_identifier': bundle.get('bundle_identifier'),
                'bundle_path': bundle.get('bundle_path'),
                'bundle_executable_path': bundle.get('executable_path') or sys.executable,
                'bundle_name': bundle.get('bundle_name'),
                'app_name': bundle.get('app_name'),
                'bundle_version': bundle.get('bundle_version'),
                'bundle_short_version': bundle.get('bundle_short_version'),
                'cwd': os.getcwd(),
                'home': os.path.expanduser('~') or str(Path.home()),
                'documents': os.path.expanduser('~/Documents'),
                'temp':  os.path.abspath(os.getenv('TMPDIR', '/tmp'))
            }

            return StructuredCommandResult(
                status=1,
                data=info,
                shape='dict',
                width=25,
            )

        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to get system info: {e}'

    # ------------------ 剪贴板 ------------------ #

    @desc('Read clipboard text', group='mobile')
    @interruptible()
    def readclip(self):
        try:
            import clipboard
            return 1, clipboard.get() or ''
        except Exception as e:
            return 0, f'Failed to read clipboard: {e}'

    @desc('Write clipboard text', group='mobile')
    @interruptible()
    def writeclip(self, text=''):
        try:
            import clipboard
            clipboard.set(text or '')
            return 1, 'Clipboard updated'
        except Exception as e:
            return 0, f'Failed to write clipboard: {e}'

    # ------------------ 手机常用 ------------------ #


    @desc('Open URL', group='mobile')
    @interruptible()
    def openurl(self, url):
        try:
            import webbrowser
            target = (url or '').strip()
            if not target:
                return 0, 'Usage: openurl <url>'
            ok = webbrowser.open(target)
            return 1, f'URL opened: {ok}'
        except Exception as e:
            return 0, f'Failed to open URL: {e}'

    @desc('Clear console output', group='mobile')
    @interruptible()
    def clearconsole(self):
        try:
            import console
            console.clear()
            return 1, 'Console cleared'
        except Exception as e:
            return 0, f'Failed to clear console: {e}'

    @desc('QuickLook preview file', group='mobile')
    @interruptible()
    def quicklook(self, path):
        try:
            import console

            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: quicklook <path>'
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'

            console.quicklook(target)
            return 1, f'Preview opened: {target}'
        except Exception as e:
            return 0, f'Failed to preview file: {e}'

    @desc('Open file in other app', group='mobile')
    @interruptible()
    def openin(self, path):
        try:
            import console

            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: openin <path>'
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'

            console.open_in(target)
            return 1, f'Open In launched: {target}'
        except Exception as e:
            return 0, f'Failed to open file externally: {e}'



    @desc('Show file stat', group='shell')
    @interruptible()
    def stat(self, path):
        try:
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: stat <path>'
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'

            st = os.stat(target)
            info = {
                'path': target,
                'is_dir': os.path.isdir(target),
                'is_file': os.path.isfile(target),
                'size': st.st_size,
                'size_human': get_size(st.st_size),
                'mtime': int(st.st_mtime),
                'ctime': int(st.st_ctime),
                'atime': int(st.st_atime),
                'mode': oct(st.st_mode),
            }
            return 1, json.dumps(info, ensure_ascii=False)
        except Exception as e:
            return 0, f'stat failed: {e}'



    @desc('Get current location', group='mobile')
    @interruptible()
    @timeout(15)
    @cancel_policy(True)
    def getlocation(self):
        try:
            import location

            location.start_updates()
            time.sleep(1.5)
            data = location.get_location()
            location.stop_updates()

            if not data:
                return 0, 'No location data'

            return 1, json.dumps(data, ensure_ascii=False)
        except CommandCancelledError:
            try:
                import location
                location.stop_updates()
            except Exception:
                pass
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            try:
                import location
                location.stop_updates()
            except Exception:
                pass
            return 0, 'Command timed out'
        except Exception as e:
            try:
                import location
                location.stop_updates()
            except Exception:
                pass
            return 0, f'Failed to get location: {e}'

    @desc('Speak text', group='mobile')
    @interruptible()
    def speak(self, text=''):
        try:
            import speech
            speech.say(text or '')
            return 1, 'Speech started'
        except Exception as e:
            return 0, f'Failed to speak text: {e}'

    @desc('List contacts via CNContactStore', group='mobile')
    @interruptible()
    def listcontacts(self, keyword=''):
        try:
            import json

            CNContactStore = ObjCClass('CNContactStore')
            CNContact = ObjCClass('CNContact')

            store = CNContactStore.alloc().init()

            keys = ns([
                'givenName',
                'familyName',
                'middleName',
                'organizationName',
                'jobTitle',
                'phoneNumbers',
                'emailAddresses',
            ])

            results = []
            seen = set()

            def contact_to_dict(c):
                family_name = str(c.familyName() or '')
                middle_name = str(c.middleName() or '')
                given_name = str(c.givenName() or '')

                full_name = ' '.join(x for x in [family_name, middle_name, given_name] if x).strip()
                if not full_name:
                    full_name = ' '.join(x for x in [given_name, middle_name, family_name] if x).strip()
                if not full_name:
                    full_name = str(c.organizationName() or '').strip() or '(no name)'

                phone_numbers = []
                nums = c.phoneNumbers()
                for j in range(int(nums.count())):
                    item = ObjCInstance(nums.objectAtIndex_(j))
                    label = str(item.label()) if item.label() else ''
                    value_obj = item.value()
                    value = str(value_obj.stringValue()) if value_obj else ''
                    if value:
                        phone_numbers.append({
                            'label': label,
                            'value': value,
                        })

                email_addresses = []
                emails = c.emailAddresses()
                for j in range(int(emails.count())):
                    item = ObjCInstance(emails.objectAtIndex_(j))
                    label = str(item.label()) if item.label() else ''
                    value = str(item.value()) if item.value() else ''
                    if value:
                        email_addresses.append({
                            'label': label,
                            'value': value,
                        })

                return {
                    'full_name': full_name,
                    'family_name': family_name,
                    'middle_name': middle_name,
                    'given_name': given_name,
                    'organization': str(c.organizationName() or ''),
                    'job_title': str(c.jobTitle() or ''),
                    'phone': phone_numbers,
                    'email': email_addresses,
                }

            keyword = (keyword or '').strip()

            if keyword:
                contacts = store.unifiedContactsMatchingPredicate_keysToFetch_error_(
                    CNContact.predicateForContactsMatchingName_(keyword),
                    keys,
                    None
                )

                for i in range(int(contacts.count())):
                    c = ObjCInstance(contacts.objectAtIndex_(i))
                    item = contact_to_dict(c)

                    uniq = (
                        item['full_name'],
                        tuple((x['label'], x['value']) for x in item['phone']),
                        tuple((x['label'], x['value']) for x in item['email']),
                    )
                    if uniq in seen:
                        continue
                    seen.add(uniq)

                    results.append(item)
            else:
                containers = store.containersMatchingPredicate_error_(None, None)

                for i in range(int(containers.count())):
                    container = ObjCInstance(containers.objectAtIndex_(i))
                    container_id = str(container.identifier())

                    contacts = store.unifiedContactsMatchingPredicate_keysToFetch_error_(
                        CNContact.predicateForContactsInContainerWithIdentifier_(container_id),
                        keys,
                        None
                    )

                    for j in range(int(contacts.count())):
                        c = ObjCInstance(contacts.objectAtIndex_(j))
                        item = contact_to_dict(c)

                        uniq = (
                            item['full_name'],
                            tuple((x['label'], x['value']) for x in item['phone']),
                            tuple((x['label'], x['value']) for x in item['email']),
                        )
                        if uniq in seen:
                            continue
                        seen.add(uniq)

                        results.append(item)

            return 1, json.dumps(results, ensure_ascii=False)

        except Exception as e:
            return 0, f'Failed to list contacts: {e}'

    @desc('Pick photo or file and upload', group='mobile')
    @interruptible()
    def pickupload(self, kind='photo'):
        try:
            import io
            import os
            import json
            import photos
            import dialogs

            kind = (kind or 'photo').strip().lower()

            if kind == 'photo':
                image = photos.pick_image()
                if image is None:
                    return 0, 'No photo selected'

                info = {
                    'type': 'photo',
                    'width': getattr(image, 'size', (None, None))[0],
                    'height': getattr(image, 'size', (None, None))[1],
                }

                buf = io.BytesIO()
                if image.mode not in ('RGB', 'L'):
                    image = image.convert('RGB')
                image.save(buf, format='JPEG', quality=90)
                buf.seek(0)

                response = upload_file_via_http(
                    file_source=buf,
                    category='Pythonista',
                    upload_url=upload_url,
                    client_id=getattr(self.socket, 'client_id', '') or '',
                    filename='photo.jpg',
                )

            elif kind == 'file':
                file_path = dialogs.pick_document()
                if not file_path:
                    return 0, 'No file selected'

                info = {
                    'type': 'file',
                    'path': file_path,
                    'filename': os.path.basename(file_path),
                }

                response = upload_file_via_http(
                    file_source=file_path,
                    category='Pythonista',
                    upload_url=upload_url,
                    filename=os.path.basename(file_path),
                    client_id=getattr(self.socket, 'client_id', '') or '',
                )

            else:
                return 0, "kind must be 'photo' or 'file'"

            result = {
                'picked': info,
                'status_code': response.status_code,
                'ok': response.ok,
            }

            try:
                result['response'] = response.json()
            except Exception:
                result['response_text'] = response.text

            return 1, json.dumps(result, ensure_ascii=False)

        except Exception as e:
            return 0, f'Failed to pick/upload: {e}'









    ALERT_ARGUMENT_SPEC = ArgumentCommandSpec(
        name='alert',
        description='Show alert dialog',
        options=[
            ArgumentOptionSpec(name='title', option_type='str', required=False, default='Alert', allow_empty=True,
                               help_text='Dialog title'),
            ArgumentOptionSpec(name='message', option_type='str', required=True, default=None, allow_empty=False,
                               help_text='Dialog text'),
            ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                               help_text='Show this help message'),
        ]
    )

    NOTIFY_ARGUMENT_SPEC = ArgumentCommandSpec(
        name='notify',
        description='Send local notification',
        options=[
            ArgumentOptionSpec(name='title', option_type='str', required=False, default='Notice', allow_empty=True,
                               help_text='Notification title'),
            ArgumentOptionSpec(name='message', option_type='str', required=True, default=None, allow_empty=False,
                               help_text='Notification text'),
            ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                               help_text='Show this help message'),
        ]
    )

    FIND_ARGUMENT_SPEC = ArgumentCommandSpec(
        name='find',
        description='Find files by keyword',
        options=[
            ArgumentOptionSpec(name='path', option_type='str', required=False, default='.', allow_empty=True,
                               help_text='Target directory'),
            ArgumentOptionSpec(name='keyword', option_type='str', required=True, default=None, allow_empty=False,
                               help_text='Keyword to search in file or directory names'),
            ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                               help_text='Show this help message'),
        ]
    )

    TREE_ARGUMENT_SPEC = ArgumentCommandSpec(
        name='tree',
        description='Show directory tree',
        options=[
            ArgumentOptionSpec(name='path', option_type='str', required=False, default='.', allow_empty=True,
                               help_text='Target directory'),
            ArgumentOptionSpec(name='max_depth', option_type='int', required=False, default=3,
                               help_text='Maximum recursion depth'),
            ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                               help_text='Show this help message'),
        ]
    )

    @argument_command('alert', spec=ALERT_ARGUMENT_SPEC)
    @interruptible()
    def alert(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            message = args_dict['message']
            import console
            button = console.alert(title or 'Alert', message or '', 'OK', hide_cancel_button=True)
            return 1, f'Alert closed: {button}'
        except Exception as e:
            return 0, f'Failed to show alert: {e}'


    @argument_command('notify', spec=NOTIFY_ARGUMENT_SPEC)
    @interruptible()
    def notify(self, args_dict, payload=None):
        try:
            title = args_dict.get('title', '')
            message = args_dict['message']
            import notification
            notification.schedule(
                message or '',
                delay=0,
                sound_name=None,
                action_url=None,
                title=title or 'Notice'
            )
            return 1, 'Notification scheduled'
        except Exception as e:
            return 0, f'Failed to send notification: {e}'

    @argument_command('find', spec=FIND_ARGUMENT_SPEC)
    @interruptible()
    def find(self, args_dict, payload=None):
        try:
            path = args_dict.get('path', '.')
            keyword = args_dict['keyword']

            target = os.path.expanduser((path or '.').strip())
            word = (keyword or '').strip()

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'
            if not word:
                return 0, 'Option "--keyword" cannot be empty'

            results = []
            for root, dirs, files in os.walk(target):
                for name in dirs + files:
                    if word.lower() in name.lower():
                        results.append(os.path.join(root, name))

            if not results:
                return 1, ''

            return 1, '\n'.join(results)
        except Exception as e:
            return 0, f'find failed: {e}'

    @argument_command('tree', spec=TREE_ARGUMENT_SPEC)
    @interruptible()
    def tree(self, args_dict, payload=None):
        try:
            path = args_dict.get('path', '.')
            max_depth = args_dict.get('max_depth', 3)

            target = os.path.expanduser((path or '.').strip())
            depth_limit = int(max_depth)

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'
            if depth_limit < 0:
                return 0, 'Option "--max_depth" must be >= 0'

            lines = [os.path.basename(target.rstrip('/')) or target]

            def walk(current, prefix='', depth=0):
                if depth >= depth_limit:
                    return

                items = sorted(
                    os.listdir(current),
                    key=lambda name: (
                        0 if os.path.isdir(os.path.join(current, name)) else 1,
                        name.lower()
                    )
                )

                for i, name in enumerate(items):
                    full = os.path.join(current, name)
                    is_last = i == len(items) - 1
                    branch = '└── ' if is_last else '├── '
                    suffix = '/' if os.path.isdir(full) else ''
                    lines.append(prefix + branch + name + suffix)

                    if os.path.isdir(full):
                        walk(full, prefix + ('    ' if is_last else '│   '), depth + 1)

            walk(target)
            return 1, '\n'.join(lines)
        except Exception as e:
            return 0, f'tree failed: {e}'

    @desc('Compute file MD5', group='shell')
    @interruptible()
    def md5sum(self, path=''):
        try:
            import hashlib
            target = os.path.expanduser((path or '').strip())
            if not target:
                return 0, 'Usage: md5sum <file>'
            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isfile(target):
                return 0, f'Not a file: {target}'

            md5 = hashlib.md5()
            with open(target, 'rb') as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    md5.update(chunk)

            return 1, f'{md5.hexdigest()}  {target}'
        except Exception as e:
            return 0, f'md5sum failed: {e}'


    @desc('Print environment variables', group='shell')
    @interruptible()
    def printenv(self, name=''):
        try:
            key = (name or '').strip()
            if key:
                return 1, str(os.environ.get(key, ''))

            lines = []
            for env_name in sorted(os.environ.keys()):
                lines.append(f'{env_name}={os.environ.get(env_name, "")}')
            return 1, '\n'.join(lines)
        except Exception as e:
            return 0, f'printenv failed: {e}'


    @desc('Echo text or expand environment variables', group='shell')
    @interruptible()
    def echo(self, text=''):
        try:
            import re
            raw = str(text or '')

            def repl(match):
                name = match.group(1) or match.group(2) or ''
                return str(os.environ.get(name, ''))

            rendered = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([^}]+)\}', repl, raw)
            return 1, rendered
        except Exception as e:
            return 0, f'echo failed: {e}'

    HEAD_ARGUMENT_SPEC = ArgumentCommandSpec(
        name='head',
        description='Show first N lines of a text file',
        options=[
            ArgumentOptionSpec(name='path', option_type='str', required=True, default=None, allow_empty=False,
                               help_text='Text file path'),
            ArgumentOptionSpec(name='lines', option_type='int', required=False, default=10,
                               help_text='Number of lines to show'),
            ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                               help_text='Show this help message'),
        ]
    )

    TAIL_ARGUMENT_SPEC = ArgumentCommandSpec(
        name='tail',
        description='Show last N lines of a text file',
        options=[
            ArgumentOptionSpec(name='path', option_type='str', required=True, default=None, allow_empty=False,
                               help_text='Text file path'),
            ArgumentOptionSpec(name='lines', option_type='int', required=False, default=10,
                               help_text='Number of lines to show'),
            ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                               help_text='Show this help message'),
        ]
    )



    WGET_ARGUMENT_SPEC = ArgumentCommandSpec(
        name='wget',
        description='Download file from URL',
        options=[
            ArgumentOptionSpec(name='url', option_type='str', required=True, default=None, allow_empty=False,
                               help_text='Source URL', positional_index=0),
            ArgumentOptionSpec(name='output', option_type='str', required=False, default='',
                               help_text='Output file path'),
            ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                               help_text='Show this help message'),
        ]
    )

    @argument_command('head', spec=HEAD_ARGUMENT_SPEC)
    @interruptible()
    def head(self, args_dict, payload=None):
        try:
            path = os.path.expanduser((args_dict.get('path') or '').strip())
            lines_count = args_dict.get('lines', 10)
            lines_count = int(lines_count)

            if not os.path.exists(path):
                return 0, f'Path not found: {path}'
            if not os.path.isfile(path):
                return 0, f'Not a file: {path}'
            if lines_count < 0:
                return 0, 'Option "--lines" must be >= 0'

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            return 1, ''.join(lines[:lines_count]).rstrip('\n')
        except Exception as e:
            return 0, f'head failed: {e}'

    @argument_command('tail', spec=TAIL_ARGUMENT_SPEC)
    @interruptible()
    def tail(self, args_dict, payload=None):
        try:
            path = os.path.expanduser((args_dict.get('path') or '').strip())
            lines_count = args_dict.get('lines', 10)
            lines_count = int(lines_count)

            if not os.path.exists(path):
                return 0, f'Path not found: {path}'
            if not os.path.isfile(path):
                return 0, f'Not a file: {path}'
            if lines_count < 0:
                return 0, 'Option "--lines" must be >= 0'

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            return 1, ''.join(lines[-lines_count:] if lines_count else []).rstrip('\n')
        except Exception as e:
            return 0, f'tail failed: {e}'


    @argument_command('wget', spec=WGET_ARGUMENT_SPEC)
    @interruptible()
    def wget(self, args_dict, payload=None):
        try:
            import urllib.request
            url = str(args_dict.get('url') or '').strip()
            out = str(args_dict.get('output') or '').strip()

            if not url:
                return 0, 'Missing required option: --url'

            if out:
                out_path = os.path.expanduser(out)
            else:
                name = url.rstrip('/').split('/')[-1] or 'download.bin'
                out_path = os.path.join(os.getcwd(), name) #默认下载到当前目录

            out_dir = os.path.dirname(out_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            with urllib.request.urlopen(url) as resp:
                with open(out_path, 'wb') as f:
                    while True:
                        chunk = resp.read(1024 * 256)
                        if not chunk:
                            break
                        f.write(chunk)

            return 1, out_path
        except Exception as e:
            return 0, f'wget failed: {e}'
