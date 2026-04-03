window.AppTerminalModule = {
    methods: {

        isFileReadyLine(line) {
            const text = (line?.text || '')
            return text.startsWith('[File Ready]')
        },

        isCommandFinishedLine(line) {
            const text = (line?.text || '')
            return text.startsWith('[Command finished]') || text.startsWith('[命令结束]')
        },

        getTerminalInlineActionItems(lines, index) {
            const line = lines[index]
            if (!line) return []

            if (!this.isFileReadyLine(line)) return []

            const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
            const usedKeysBefore = this.getUsedInlineActionKeysBeforeLine(lines, index)

            const previewItem = groupItems.find(item => {
                return item.type === 'preview' && !usedKeysBefore.has(item.key)
            })

            return previewItem ? [previewItem] : []
        },

        getTerminalTailActionItems(lines, index) {
            const line = lines[index]
            if (!line || !this.isCommandFinishedLine(line)) return []

            const groupItems = this.getTerminalCommandGroupActionItems(lines, index) || []
            const usedKeysUpToCurrent = this.getUsedInlineActionKeysUpToLine(lines, index)

            return groupItems.filter(item => !usedKeysUpToCurrent.has(item.key))
        },

        getUsedInlineActionKeysBeforeLine(lines, endIndexExclusive) {
            const used = new Set()

            for (let i = 0; i < endIndexExclusive; i += 1) {
                const line = lines[i]
                if (!this.isFileReadyLine(line)) continue

                const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
                const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

                if (previewItem) {
                    used.add(previewItem.key)
                }
            }

            return used
        },

        getUsedInlineActionKeysUpToLine(lines, endIndexInclusive) {
            const used = new Set()

            for (let i = 0; i <= endIndexInclusive; i += 1) {
                const line = lines[i]
                if (!this.isFileReadyLine(line)) continue

                const groupItems = this.getTerminalCommandGroupActionItems(lines, i) || []
                const previewItem = groupItems.find(item => item.type === 'preview' && !used.has(item.key))

                if (previewItem) {
                    used.add(previewItem.key)
                }
            }

            return used
        },
    }
}