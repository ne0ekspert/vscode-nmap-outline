// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

class NmapNormalOutputSymbolProvider implements vscode.DocumentSymbolProvider {
    private openPortRegex = /^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)/;
    private hiddenPortRegex = /^Not shown:\s+(\d+)\s+(closed|filtered)\s+\w+\s+ports\s+\(([^)]+)\)/;
    private hostStatusRegex = /^Host is (up|down).*/;
    private macRegex = /^MAC Address:\s+([0-9A-Fa-f:]{17})\s+\(([^)]+)\)/;
    private deviceTypeRegex = /^Device type:\s+(.+)$/;
    private runningRegex = /^Running:\s+(.+)$/;
    private osCpeRegex = /^OS CPE:\s+(.+)$/;
    private osDetailsRegex = /^OS details:\s+(.+)$/;
    private fingerprintStartRegex = /^TCP\/IP fingerprint:/;
    private osFingerprintLineRegex = /^OS:(.+)$/;
    private uptimeRegex = /^Uptime guess:\s+(.+)$/;
    private distanceRegex = /^Network Distance:\s+(.+)$/;
    private tcpSequenceRegex = /^TCP Sequence Prediction:\s+(.+)$/;
    private ipIdRegex = /^IP ID Sequence Generation:\s+(.+)$/;

    private ensureGroup(parent: vscode.DocumentSymbol, groupRef: { current?: vscode.DocumentSymbol }, label: string, detail: string, range: vscode.Range): vscode.DocumentSymbol {
        if (!groupRef.current) {
            groupRef.current = new vscode.DocumentSymbol(
                label,
                detail,
                vscode.SymbolKind.Namespace,
                range,
                range
            );
            parent.children.push(groupRef.current);
        }
        return groupRef.current;
    }

    public async provideDocumentSymbols(
        document: vscode.TextDocument,
        token: vscode.CancellationToken
    ): Promise<vscode.DocumentSymbol[]> {
        const symbols: vscode.DocumentSymbol[] = [];
        let currentHost: vscode.DocumentSymbol | undefined;
        let metadataGroup: { current?: vscode.DocumentSymbol } = {};
        let portSummaryGroup: { current?: vscode.DocumentSymbol } = {};
        let osCpeGroup: { current?: vscode.DocumentSymbol } = {};

        for (let i = 0; i < document.lineCount; i++) {
            if (token.isCancellationRequested) {
                return symbols;
            }

            const line = document.lineAt(i);
            const text = line.text;

            if (text.startsWith('Nmap scan report for')) {
                currentHost = new vscode.DocumentSymbol(
                    text.slice(21),
                    'Host',
                    vscode.SymbolKind.Class,
                    line.range,
                    line.range
                );
                symbols.push(currentHost);
                metadataGroup = {};
                portSummaryGroup = {};
                osCpeGroup = {};
                continue;
            }

            if (!currentHost) {
                continue;
            }

            if (this.hostStatusRegex.test(text)) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'Host status',
                        text.replace(/^Host is\s+/, ''),
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            if (text.startsWith('Aggressive OS guesses:')) {
                const guesses = text.slice(23).split(', ');
                const guessesSymbol = new vscode.DocumentSymbol(
                    'Aggressive OS Guess',
                    '',
                    vscode.SymbolKind.Module,
                    line.range,
                    line.range
                );

                guesses.forEach((guess) => {
                    const symbol = new vscode.DocumentSymbol(
                        guess,
                        'OS Guess',
                        vscode.SymbolKind.Object,
                        line.range,
                        line.range
                    );
                    guessesSymbol.children.push(symbol);
                });

                currentHost.children.push(guessesSymbol);
                continue;
            }

            const openMatch = text.match(this.openPortRegex);
            if (openMatch) {
                const symbolKind = (() => {
                    switch (openMatch[3]) {
                        case 'open':
                            return vscode.SymbolKind.Interface;
                        case 'closed':
                            return vscode.SymbolKind.Null;
                        case 'filtered':
                            return vscode.SymbolKind.Number;
                        default:
                            return vscode.SymbolKind.Number;
                    }
                })();

                const group = this.ensureGroup(currentHost, portSummaryGroup, 'Port summary', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        String(openMatch[1]),
                        openMatch[4],
                        symbolKind,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const hiddenMatch = text.match(this.hiddenPortRegex);
            if (hiddenMatch) {
                const group = this.ensureGroup(currentHost, portSummaryGroup, 'Port summary', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        `Not shown (${hiddenMatch[1]})`,
                        `${hiddenMatch[2]} (${hiddenMatch[3]})`,
                        vscode.SymbolKind.Property,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const macMatch = text.match(this.macRegex);
            if (macMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'MAC Address',
                        `${macMatch[1]} (${macMatch[2]})`,
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const deviceTypeMatch = text.match(this.deviceTypeRegex);
            if (deviceTypeMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'Device type',
                        deviceTypeMatch[1],
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const runningMatch = text.match(this.runningRegex);
            if (runningMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'Running',
                        runningMatch[1],
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const osCpeMatch = text.match(this.osCpeRegex);
            if (osCpeMatch) {
                const group = this.ensureGroup(currentHost, osCpeGroup, 'OS CPE', '', line.range);
                osCpeMatch[1].split(/\s+/).filter(Boolean).forEach((cpe) => {
                    group.children.push(
                        new vscode.DocumentSymbol(
                            cpe,
                            '',
                            vscode.SymbolKind.Constant,
                            line.range,
                            line.range
                        )
                    );
                });
                continue;
            }

            const osDetailsMatch = text.match(this.osDetailsRegex);
            if (osDetailsMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'OS details',
                        osDetailsMatch[1],
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            if (this.fingerprintStartRegex.test(text)) {
                let endLine = line.range;
                let j = i + 1;
                for (; j < document.lineCount; j++) {
                    const next = document.lineAt(j);
                    if (!this.osFingerprintLineRegex.test(next.text.trim())) {
                        break;
                    }
                    endLine = next.range;
                }

                const range = new vscode.Range(line.range.start, endLine.end);
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'TCP/IP fingerprint',
                        '',
                        vscode.SymbolKind.Struct,
                        range,
                        range
                    )
                );

                i = j - 1;
                continue;
            }

            const uptimeMatch = text.match(this.uptimeRegex);
            if (uptimeMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'Uptime guess',
                        uptimeMatch[1],
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const distanceMatch = text.match(this.distanceRegex);
            if (distanceMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'Network Distance',
                        distanceMatch[1],
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const tcpSeqMatch = text.match(this.tcpSequenceRegex);
            if (tcpSeqMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'TCP Sequence Prediction',
                        tcpSeqMatch[1],
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
                continue;
            }

            const ipIdMatch = text.match(this.ipIdRegex);
            if (ipIdMatch) {
                const group = this.ensureGroup(currentHost, metadataGroup, 'Host details', '', line.range);
                group.children.push(
                    new vscode.DocumentSymbol(
                        'IP ID Sequence Generation',
                        ipIdMatch[1],
                        vscode.SymbolKind.Field,
                        line.range,
                        line.range
                    )
                );
            }
        }

        return symbols;
    }
}

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.languages.registerDocumentSymbolProvider(
            {scheme: "file", language: "nmap-oN"}, 
            new NmapNormalOutputSymbolProvider())
    );
}

// This method is called when your extension is deactivated
export function deactivate() {}
