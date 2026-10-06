# Shared, fail-closed declaration discovery for this fixed proof layout.
function Get-LibrarySources {
    foreach ($library in @('FooLiL2','FooLiL3')) {
        Get-ChildItem -LiteralPath $library -Filter '*.lean' -File | Sort-Object Name
    }
}

function Get-LibraryDeclarations {
    foreach ($file in (Get-LibrarySources)) {
        $source = [System.IO.File]::ReadAllText($file.FullName)
        $namespaces = [regex]::Matches($source, '(?m)^namespace\s+([\w.]+)\s*$')
        if ($namespaces.Count -ne 1) { throw "Review namespace layout: $($file.Name)" }
        $prefix = $namespaces[0].Groups[1].Value + '.'
        $relative = $file.Directory.Name + '/' + $file.Name
        foreach ($match in [regex]::Matches($source,
            '(?m)^(?:@\[[^\]]+\]\s*)?(?:noncomputable\s+)?(theorem|def|lemma|instance)\s+([\w\x27]+)')) {
            [ordered]@{kind=$match.Groups[1].Value; name=$prefix + $match.Groups[2].Value; file=$relative}
        }
    }
}
