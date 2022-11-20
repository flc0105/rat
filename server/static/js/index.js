axios.interceptors.response.use(res => {
    if (res.status === 200) {
        return res.data
    }
})

const url = location.protocol + '//' + location.host

function escape(text) {
    return text.replace(/&/g, '&amp;').replace(/>/g, '&gt;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
}

const app = Vue.createApp({
    data() {
        return {
            connections: [],
            target: '',
            command: '',
            cwd: '',
            output: '',
            wait: false,
        }
    },
    methods: {
        list() {
            axios.post(url + '/list')
                .then((res) => {
                    this.connections = res
                    if (res.length > 0) {
                        this.target = res[0]
                    }
                })
                .catch((err) => {
                    alert(err.message)
                })
        },
        execute() {
            if (this.command.trim().length == 0 || this.target == '') {
                return
            }
            this.wait = true
            axios.post(url + '/execute', { 'target': this.target.id, 'command': this.command })
                .then((res) => {
                    status = res['status']
                    cwd = res['cwd']
                    result = escape(res['result'])
                    result = status == '1' ? result : '<span style="color: red">' + result + '</span>'
                    file = res['file']
                    if (file != null) {
                        result += '\n<a href="' + url + '/download/' + file + '">Download</a>'
                    }
                    this.output += this.cwd + '> ' + this.command + '\n' + result + '\n'
                    this.cwd = cwd
                    this.command = ''
                })
                .catch((err) => {
                    alert(err.message)
                })
                .finally(() => {
                    this.wait = false
                })
        },
        upload(event) {
            if (this.target == '') {
                return
            }
            this.wait = true
            const formData = new FormData()
            formData.append('target', this.target.id)
            formData.append('file', event.target.files[0])
            axios.post(url + '/upload', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            })
                .then(res => {
                    alert(res)
                })
                .catch(err => {
                    alert(err)
                })
                .finally(() => {
                    this.wait = false
                })
        },
        screenshot() {
            if (this.target == '') {
                return
            }
            this.wait = true
            axios.post(url + '/execute', { 'target': this.target.id, 'command': 'screenshot' })
                .then((res) => {
                    file = res['file']
                    if (file != null) {
                        window.open(url + '/download/' + file, '_blank')
                    } else {
                        alert('Screen grab failed: ' + res['result'])
                    }
                })
                .catch((err) => {
                    alert(err.message)
                })
                .finally(() => {
                    this.wait = false
                })
        }
    },
    mounted() {
        this.list()
    },
    updated() {
        var result = document.getElementById('result')
        result.scrollTop = result.scrollHeight
        document.getElementById('command').focus()
    }
})

app.mount('body')
