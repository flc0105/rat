import json
import os
import platform
import shutil
import sys
import time

from objc_util import ObjCClass, ns, ObjCInstance

from client.commands.argument_command_registry import argument_command, ArgumentCommandSpec, ArgumentOptionSpec
from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.common import CommonCommands
from client.commands.interrupts import timeout, cancel_policy, interruptible
from client.config.config import UPLOAD_BASE_URL
from client.config.runtime_config import HTTP_TRANSFER_MODE
from core.utils.decorator import desc
from core.utils.logger import logger

upload_url = UPLOAD_BASE_URL.rstrip('/') + '/api/files/upload'


def upload_file_via_http(
        file_source,
        category=None,
        filename=None
):
    import os
    import requests

    form_data = {
        'artifact_type': 'files',
        'category': (category or '').strip() or 'default',
    }

    close_after = False

    if isinstance(file_source, str):
        file_obj = open(file_source, 'rb')
        close_after = True
        upload_name = filename or os.path.basename(file_source)
    else:
        file_obj = file_source
        upload_name = filename or getattr(file_obj, 'name', None) or 'upload.bin'

    try:
        # 尽量从头开始读
        try:
            file_obj.seek(0)
        except Exception:
            pass

        files = {
            'file': (upload_name, file_obj)
        }

        response = requests.post(
            upload_url,
            files=files,
            data=form_data,
            timeout=30,
        )

        try:
            payload = response.json()
        except Exception:
            payload = None

        if response.ok and isinstance(payload, dict):
            file_info = payload.get('data') or {}

        return response

    finally:
        if close_after:
            try:
                file_obj.close()
            except Exception:
                pass


def uptime_to_text(seconds):
    try:
        seconds = int(seconds)
    except Exception:
        return None

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"


def _safe_call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _format_bytes(value):
    try:
        size = float(value)
    except Exception:
        return None

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f'{size:.2f} {unit}'
        size /= 1024.0
    return str(value)


def _get_username():
    for key in ('USER', 'LOGNAME', 'USERNAME'):
        value = os.environ.get(key)
        if value:
            return value
    return _safe_call(os.getlogin, 'unknown')


def _get_process_name():
    argv0 = sys.argv[0] if sys.argv else ''
    if argv0:
        return os.path.basename(argv0)
    return os.path.basename(sys.executable or '') or 'python'


def _get_bundle_info():
    info = {
        'bundle_identifier': None,
        'bundle_path': None,
        'executable_path': None,
        'resource_path': None,
        'bundle_name': None,
        'app_name': None,
        'bundle_version': None,
        'bundle_short_version': None,
    }

    try:
        NSBundle = ObjCClass('NSBundle')
        bundle = NSBundle.mainBundle()

        info['bundle_identifier'] = _safe_call(lambda: str(bundle.bundleIdentifier()))
        info['bundle_path'] = _safe_call(lambda: str(bundle.bundlePath()))
        info['executable_path'] = _safe_call(lambda: str(bundle.executablePath()))
        info['resource_path'] = _safe_call(lambda: str(bundle.resourcePath()))

        info_dict = _safe_call(lambda: bundle.infoDictionary())
        if info_dict is not None:
            def get_value(key):
                value = info_dict.objectForKey_(key)
                return str(value) if value is not None else None

            info['bundle_name'] = _safe_call(lambda: get_value('CFBundleName'))
            info['app_name'] = _safe_call(lambda: get_value('CFBundleDisplayName')) or _safe_call(
                lambda: get_value('CFBundleName'))
            info['bundle_version'] = _safe_call(lambda: get_value('CFBundleVersion'))
            info['bundle_short_version'] = _safe_call(lambda: get_value('CFBundleShortVersionString'))
    except Exception:
        pass

    return info


def _get_device_info():
    info = {
        'device_name': None,
        'device_model': None,
        'device_localized_model': None,
        'device_type': None,
        'system': None,
        'system_version': None,
        'machine_name': None,
        'hostname': None,
        'identifier_for_vendor': None,
    }

    try:
        UIDevice = ObjCClass('UIDevice')
        device = UIDevice.currentDevice()

        idiom_map = {
            0: "Phone",
            1: "Pad",
            2: "TV",
            3: "CarPlay",
            4: "Mac",
            5: "Vision",
        }

        info['device_name'] = _safe_call(lambda: str(device.name()))
        info['device_model'] = _safe_call(lambda: str(device.model()))
        info['device_localized_model'] = _safe_call(lambda: str(device.localizedModel()))
        info['system'] = _safe_call(lambda: str(device.systemName()))
        info['system_version'] = _safe_call(lambda: str(device.systemVersion()))
        info['device_type'] = _safe_call(
            lambda: idiom_map.get(int(device.userInterfaceIdiom()), str(int(device.userInterfaceIdiom()))))

        identifier_for_vendor = _safe_call(lambda: device.identifierForVendor())
        if identifier_for_vendor is not None:
            info['identifier_for_vendor'] = _safe_call(lambda: str(identifier_for_vendor.UUIDString()))
    except Exception:
        pass

    try:
        uname_info = os.uname()
        info['machine_name'] = uname_info.machine
        info['hostname'] = uname_info.nodename
    except Exception:
        pass

    return info


def _get_process_info():
    info = {
        'process_name': None,
        'process_id': None,
        'username': None,
        'arguments': None,
        'processor_count': None,
        'active_processor_count': None,
        'physical_memory_bytes': None,
        'physical_memory_human': None,
        'system_boot_time': None,
        'system_uptime_seconds': None,
        'system_uptime_human': None,
        'operating_system_version_string': None,
        'low_power_mode_enabled': None,
    }

    try:
        NSProcessInfo = ObjCClass('NSProcessInfo')
        proc = NSProcessInfo.processInfo()

        info['process_name'] = _safe_call(lambda: str(proc.processName()))
        info['process_id'] = _safe_call(lambda: int(proc.processIdentifier()))
        info['username'] = _safe_call(lambda: str(proc.userName()))
        info['arguments'] = _safe_call(lambda: [str(x) for x in list(proc.arguments())])

        info['processor_count'] = _safe_call(lambda: int(proc.processorCount()))
        info['active_processor_count'] = _safe_call(lambda: int(proc.activeProcessorCount()))

        physical_memory = _safe_call(lambda: int(proc.physicalMemory()))
        info['physical_memory_bytes'] = physical_memory
        info['physical_memory_human'] = _format_bytes(physical_memory) if physical_memory is not None else None

        system_uptime = _safe_call(lambda: int(proc.systemUptime()))
        info['system_uptime_seconds'] = system_uptime
        info['system_uptime_human'] = uptime_to_text(system_uptime) if system_uptime is not None else None
        info['system_boot_time'] = int(time.time() - system_uptime) if system_uptime is not None else None

        info['operating_system_version_string'] = _safe_call(lambda: str(proc.operatingSystemVersionString()))
        info['low_power_mode_enabled'] = _safe_call(lambda: bool(proc.isLowPowerModeEnabled()))
    except Exception:
        pass

    return info


class iOSCommands(CommonCommands):
    """iOS / Pythonista 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)

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
            return 1, str(_get_username())
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
            device = _get_device_info()
            proc = _get_process_info()
            bundle = _get_bundle_info()

            info = {
                'device_name': device.get('device_name'),
                'device_model': device.get('device_model'),
                'device_localized_model': device.get('device_localized_model'),
                'device_type': device.get('device_type'),
                'machine_name': device.get('machine_name'),
                'hostname': device.get('hostname'),
                'system': device.get('system'),
                'system_version': device.get('system_version'),
                'identifier_for_vendor': device.get('identifier_for_vendor'),

                'platform': _safe_call(platform.platform),
                'release': _safe_call(platform.release),
                'version': _safe_call(platform.version),
                'machine': _safe_call(platform.machine),
                'python_compiler': _safe_call(platform.python_compiler),
                'python_version': sys.version,
                'python_version_short': _safe_call(platform.python_version),

                'process_name': proc.get('process_name'),
                'process_id': proc.get('process_id'),
                'username': proc.get('username'),
                'startup_args': proc.get('arguments'),
                'processor_count': proc.get('processor_count'),
                'active_processor_count': proc.get('active_processor_count'),
                'physical_memory_bytes': proc.get('physical_memory_bytes'),
                'physical_memory_human': proc.get('physical_memory_human'),
                'system_boot_time': proc.get('system_boot_time'),
                'system_uptime_seconds': proc.get('system_uptime_seconds'),
                'system_uptime_human': proc.get('system_uptime_human'),
                'operating_system_version_string': proc.get('operating_system_version_string'),
                'low_power_mode_enabled': proc.get('low_power_mode_enabled'),

                'bundle_identifier': bundle.get('bundle_identifier'),
                'bundle_path': bundle.get('bundle_path'),
                'executable_path': bundle.get('executable_path'),
                'resource_path': bundle.get('resource_path'),
                'bundle_name': bundle.get('bundle_name'),
                'app_name': bundle.get('app_name'),
                'bundle_version': bundle.get('bundle_version'),
                'bundle_short_version': bundle.get('bundle_short_version'),

                'executable': sys.executable,
                'home': os.path.expanduser('~'),
                'cwd': os.getcwd(),
                'pythonista_home':  str(Path.home()),
                'documents': os.path.expanduser('~/Documents'),
                'temp':  os.path.abspath(os.getenv('TMPDIR', '/tmp'))
            }

            return 1, json.dumps(info, ensure_ascii=False)
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
                'size_human': _format_bytes(st.st_size),
                'mtime': int(st.st_mtime),
                'ctime': int(st.st_ctime),
                'atime': int(st.st_atime),
                'mode': oct(st.st_mode),
            }
            return 1, json.dumps(info, ensure_ascii=False)
        except Exception as e:
            return 0, f'stat failed: {e}'




    # @desc('Pick photo from library', group='mobile')
    # @interruptible()
    # def pickphoto(self):
    #     try:
    #         import photos
    #
    #         image = photos.pick_image()
    #         if image is None:
    #             return 0, 'No photo selected'
    #
    #         info = {
    #             'width': getattr(image, 'size', (None, None))[0],
    #             'height': getattr(image, 'size', (None, None))[1],
    #         }
    #
    #         import io
    #         buf = io.BytesIO()
    #         if image.mode not in ('RGB', 'L'):
    #             image = image.convert('RGB')
    #         image.save(buf, format='JPEG', quality=90)
    #         buf.seek(0)
    #
    #         response = upload_file_via_http(
    #             buf,
    #             category='pythonista',
    #             filename='photo.jpg',
    #         )
    #
    #         return 1, json.dumps(info, ensure_ascii=False)
    #     except Exception as e:
    #         return 0, f'Failed to pick photo: {e}'
    #
    # @desc('Save image file to Photos', group='mobile')
    # @interruptible()
    # def savephoto(self, path):
    #     try:
    #         import photos
    #         from PIL import Image
    #
    #         target = os.path.expanduser((path or '').strip())
    #         if not target:
    #             return 0, 'Usage: savephoto <image_path>'
    #         if not os.path.exists(target):
    #             return 0, f'Path not found: {target}'
    #         if not os.path.isfile(target):
    #             return 0, f'Not a file: {target}'
    #
    #         image = Image.open(target)
    #         photos.save_image(image)
    #         return 1, f'Saved to Photos: {target}'
    #     except Exception as e:
    #         return 0, f'Failed to save photo: {e}'

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
                    buf,
                    category='pythonista',
                    filename='photo.jpg',
                    # content_type='image/jpeg',
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
                    file_path,
                    category='pythonista',
                    filename=os.path.basename(file_path)
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



    @desc('Find files by keyword', group='shell')
    @interruptible()
    def find(self, path='.', keyword=''):
        try:
            target = os.path.expanduser((path or '.').strip())
            word = (keyword or '').strip()

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'
            if not word:
                return 0, 'Usage: find <path> <keyword>'

            results = []
            for root, dirs, files in os.walk(target):
                for name in dirs + files:
                    if word.lower() in name.lower():
                        results.append(os.path.join(root, name))

            return 1, '\n'.join(results)
        except Exception as e:
            return 0, f'find failed: {e}'

    @desc('Show directory tree', group='shell')
    @interruptible()
    def tree(self, path='.', max_depth='3'):
        try:
            target = os.path.expanduser((path or '.').strip())
            depth_limit = int(max_depth)

            if not os.path.exists(target):
                return 0, f'Path not found: {target}'
            if not os.path.isdir(target):
                return 0, f'Not a directory: {target}'

            lines = [os.path.basename(target.rstrip('/')) or target]

            def walk(current, prefix='', depth=0):
                if depth >= depth_limit:
                    return
                items = sorted(os.listdir(current),
                               key=lambda name: (0 if os.path.isdir(os.path.join(current, name)) else 1, name.lower()))
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
