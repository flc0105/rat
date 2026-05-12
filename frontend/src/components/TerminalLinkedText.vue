<template>
  <span class="terminal-linked-text">
    <template
        v-for="segment in segments"
        :key="segment.key"
    >
      <span v-if="!segment.isUrl">{{ segment.text }}</span>

      <button
          v-else
          class="terminal-url-link"
          type="button"
          :title="segment.url"
          @click.prevent.stop="openUrlMenu(segment, $event)"
      >
        {{ segment.text }}
      </button>
    </template>
  </span>

  <teleport to="body">
    <div
        v-if="activeUrlSegment"
        ref="urlMenuRef"
        class="terminal-url-floating-menu"
        :style="urlMenuStyle"
        @click.stop
    >
      <button
          class="terminal-url-menu-item"
          type="button"
          @click="handleUrlCommand('copy')"
      >
        Copy URL
      </button>
      <button
          class="terminal-url-menu-item"
          type="button"
          @click="handleUrlCommand('open')"
      >
        Open in new tab
      </button>
    </div>
  </teleport>
</template>

<script>
import {ElMessage} from 'element-plus'

const TERMINAL_URL_RE = /(https?:\/\/[^\s"'<>`]+|ftp:\/\/[^\s"'<>`]+|www\.[^\s"'<>`]+)/gi
const TRAILING_URL_PUNCTUATION_RE = /[),.;:!?\]}]+$/

export default {
  name: 'TerminalLinkedText',

  props: {
    text: {
      type: [String, Number],
      default: '',
    },
  },

  data() {
    return {
      activeUrlSegment: null,
      menuAnchorX: 0,
      menuAnchorY: 0,
      menuX: 0,
      menuY: 0,
      menuListenersAttached: false,
    }
  },

  computed: {
    segments() {
      return this.parseTerminalTextLinks(String(this.text ?? ''))
    },

    urlMenuStyle() {
      return {
        left: `${this.menuX}px`,
        top: `${this.menuY}px`,
      }
    },
  },

  beforeUnmount() {
    this.detachFloatingMenuListeners()
  },

  methods: {
    parseTerminalTextLinks(text) {
      if (!text) return [{key: 'text-0', text: '', isUrl: false}]

      const segments = []
      const matcher = new RegExp(TERMINAL_URL_RE.source, TERMINAL_URL_RE.flags)
      let lastIndex = 0
      let match = matcher.exec(text)

      while (match) {
        const rawMatch = match[0]
        const matchStart = match.index
        const matchEnd = matcher.lastIndex
        const cleanUrlText = rawMatch.replace(TRAILING_URL_PUNCTUATION_RE, '')
        const trailingText = rawMatch.slice(cleanUrlText.length)

        if (matchStart > lastIndex) {
          segments.push({
            key: `text-${segments.length}-${lastIndex}`,
            text: text.slice(lastIndex, matchStart),
            isUrl: false,
          })
        }

        if (cleanUrlText) {
          segments.push({
            key: `url-${segments.length}-${matchStart}`,
            text: cleanUrlText,
            url: cleanUrlText,
            isUrl: true,
          })
        }

        if (trailingText) {
          segments.push({
            key: `text-${segments.length}-${matchStart}-trail`,
            text: trailingText,
            isUrl: false,
          })
        }

        lastIndex = matchEnd
        match = matcher.exec(text)
      }

      if (lastIndex < text.length) {
        segments.push({
          key: `text-${segments.length}-${lastIndex}`,
          text: text.slice(lastIndex),
          isUrl: false,
        })
      }

      return segments.length ? segments : [{key: 'text-0', text, isUrl: false}]
    },

    openUrlMenu(segment, event) {
      this.activeUrlSegment = segment
      this.menuAnchorX = event.clientX
      this.menuAnchorY = event.clientY
      this.menuX = event.clientX + 8
      this.menuY = event.clientY + 8

      this.$nextTick(() => {
        this.clampFloatingMenuPosition()
        this.attachFloatingMenuListeners()
      })
    },

    clampFloatingMenuPosition() {
      const menu = this.$refs.urlMenuRef
      if (!menu) return

      const margin = 8
      const gap = 8
      const rect = menu.getBoundingClientRect()
      const viewportWidth = window.innerWidth || document.documentElement.clientWidth
      const viewportHeight = window.innerHeight || document.documentElement.clientHeight

      let left = this.menuAnchorX + gap
      let top = this.menuAnchorY + gap

      if (left + rect.width > viewportWidth - margin) {
        left = this.menuAnchorX - rect.width - gap
      }

      if (top + rect.height > viewportHeight - margin) {
        top = this.menuAnchorY - rect.height - gap
      }

      this.menuX = Math.max(margin, Math.min(left, viewportWidth - rect.width - margin))
      this.menuY = Math.max(margin, Math.min(top, viewportHeight - rect.height - margin))
    },

    attachFloatingMenuListeners() {
      if (this.menuListenersAttached) return
      this.menuListenersAttached = true
      window.addEventListener('resize', this.closeUrlMenu)
      window.addEventListener('scroll', this.closeUrlMenu, true)
      window.addEventListener('keydown', this.handleFloatingMenuKeydown)
      window.setTimeout(() => {
        if (this.menuListenersAttached) {
          document.addEventListener('click', this.closeUrlMenu)
        }
      }, 0)
    },

    detachFloatingMenuListeners() {
      if (!this.menuListenersAttached) return
      this.menuListenersAttached = false
      window.removeEventListener('resize', this.closeUrlMenu)
      window.removeEventListener('scroll', this.closeUrlMenu, true)
      window.removeEventListener('keydown', this.handleFloatingMenuKeydown)
      document.removeEventListener('click', this.closeUrlMenu)
    },

    closeUrlMenu() {
      this.activeUrlSegment = null
      this.detachFloatingMenuListeners()
    },

    handleFloatingMenuKeydown(event) {
      if (event.key === 'Escape') {
        this.closeUrlMenu()
      }
    },

    normalizeUrlForOpen(url) {
      const value = String(url || '').trim()
      if (!value) return ''
      return /^(?:https?:\/\/|ftp:\/\/)/i.test(value) ? value : `http://${value}`
    },

    async handleUrlCommand(command) {
      const rawUrl = String(this.activeUrlSegment?.url || '').trim()
      if (!rawUrl) return

      if (command === 'copy') {
        try {
          await this.copyTextToClipboard(rawUrl)
          ElMessage.success('URL copied')
        } catch (e) {
          ElMessage.error(e.message || 'Copy failed')
        } finally {
          this.closeUrlMenu()
        }
        return
      }

      if (command === 'open') {
        const targetUrl = this.normalizeUrlForOpen(rawUrl)
        if (targetUrl) {
          window.open(targetUrl, '_blank', 'noopener,noreferrer')
        }
        this.closeUrlMenu()
      }
    },

    async copyTextToClipboard(text) {
      if (
          typeof navigator !== 'undefined' &&
          navigator.clipboard &&
          typeof navigator.clipboard.writeText === 'function'
      ) {
        await navigator.clipboard.writeText(text)
        return
      }

      const textarea = document.createElement('textarea')
      textarea.value = text
      textarea.setAttribute('readonly', 'readonly')
      textarea.style.position = 'fixed'
      textarea.style.left = '-9999px'
      textarea.style.top = '-9999px'
      document.body.appendChild(textarea)
      textarea.select()

      const ok = document.execCommand('copy')
      document.body.removeChild(textarea)

      if (!ok) {
        throw new Error('Copy failed')
      }
    },
  },
}
</script>

<style scoped>
.terminal-linked-text {
  min-width: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.terminal-url-link {
  display: inline;
  padding: 0 1px;
  border: 0;
  border-radius: 3px;
  background: transparent;
  color: #60a5fa;
  font: inherit;
  line-height: inherit;
  text-align: left;
  /*text-decoration: underline;*/
  text-decoration-thickness: 1px;
  text-underline-offset: 3px;
  cursor: pointer;
  transition: color 0.14s ease,
  background 0.14s ease,
  text-shadow 0.14s ease;
}

.terminal-url-link:hover,
.terminal-url-link:focus-visible {
  background: rgba(96, 165, 250, 0.12);
  color: #93c5fd;
  text-shadow: 0 0 12px rgba(96, 165, 250, 0.36);
  outline: none;
}

.terminal-url-floating-menu {
  position: fixed;
  z-index: 5000;
  min-width: 144px;
  padding: 5px;
  border: 1px solid rgba(148, 163, 184, 0.24);
  border-radius: 10px;
  background: rgba(15, 23, 42, 0.96);
  box-shadow: 0 14px 34px rgba(0, 0, 0, 0.34),
  0 0 0 1px rgba(255, 255, 255, 0.04) inset;
  backdrop-filter: blur(10px);
}

.terminal-url-menu-item {
  display: block;
  width: 100%;
  height: 28px;
  padding: 0 10px;
  border: 0;
  border-radius: 7px;
  background: transparent;
  color: rgba(226, 232, 240, 0.94);
  font-size: 12px;
  line-height: 28px;
  text-align: left;
  cursor: pointer;
}

.terminal-url-menu-item:hover,
.terminal-url-menu-item:focus-visible {
  background: rgba(96, 165, 250, 0.14);
  color: #bfdbfe;
  outline: none;
}
</style>
