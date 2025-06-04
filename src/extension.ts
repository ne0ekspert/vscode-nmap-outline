// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

class NmapNormalOutputSymbolProvider implements vscode.DocumentSymbolProvider {
    private openPortRegex = /^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)/;

    private async processChunk(document: vscode.TextDocument, start: number, size: number, token: vscode.CancellationToken): Promise<vscode.DocumentSymbol[]> {
        const chunk: vscode.DocumentSymbol[] = [];

        for (let i = start; i < Math.min(start + size, document.lineCount); i++) {
            let line = document.lineAt(i);
            console.log(`Processing line ${i}`);

            if (token.isCancellationRequested) {
                return chunk;
            }

            if (line.text.startsWith("Nmap scan report for")) {
                const symbol = new vscode.DocumentSymbol(
                    line.text.slice(21), 'IP',
                    vscode.SymbolKind.Class,
                    line.range, line.range);
                chunk.push(symbol);
            } else if (line.text.startsWith("Aggressive OS guesses:")) {
                const guesses = line.text.slice(23).split(', ');

                const parent_symbol = new vscode.DocumentSymbol(
                    'Aggressive OS Guess', '',
                    vscode.SymbolKind.Module,
                    line.range, line.range);
                    
                    guesses.forEach((guess) => {
                        const symbol = new vscode.DocumentSymbol(
                        guess, 'OS Guess',
                        vscode.SymbolKind.Object,
                        line.range, line.range);
                        parent_symbol.children.push(symbol);
                    });

                    chunk[chunk.length - 1].children.push(parent_symbol);
                } else if (this.openPortRegex.test(line.text)) {
                const match = line.text.match(this.openPortRegex);
                if (!match) {
                    continue;
                }

                const symbolkind = (() => {
                    switch(match[3]) {
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

                let symbol = new vscode.DocumentSymbol(
                    String(match[1]), match[4],
                    symbolkind, 
                    line.range, line.range);
                chunk[chunk.length - 1].children.push(symbol);
            }
        }

        return chunk;
    }

    public async provideDocumentSymbols(
        document: vscode.TextDocument,
        token: vscode.CancellationToken): Promise<vscode.DocumentSymbol[]> {
        const symbols: vscode.DocumentSymbol[] = [];
        const chunkSize = 10; // Adjust this value based on performance needs

        for (let i = 0; i < document.lineCount; i += chunkSize) {
            const chunk = await this.processChunk(document, i, chunkSize, token);
            symbols.push(...chunk);
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
