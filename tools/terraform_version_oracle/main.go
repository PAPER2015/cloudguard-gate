// Terraform이 provider 버전 제약을 평가하는 것과 같은 라이브러리·함수로 계산하는 기준(oracle) 프로그램.
//
// 입력(한 줄에 하나, '#' 으로 시작하는 줄은 설명):
//
//	제약                → 출력 JSON majors[제약] = 만족하는 버전이 있는 메이저 목록(1~7) 또는 "error"
//	제약 @@ 정확한버전  → 출력 JSON members[줄]  = 그 버전이 제약을 만족하는지(true/false) 또는 "error"
//
// 후보 버전은 촘촘한 표본이 아니라 "제약에 적힌 경계값"에서 만든다.
// 제약을 만족하는 정식 버전 집합은 (경계값으로 정해지는 구간) - (!= 로 뺀 점 몇 개) 이므로,
// 그 집합이 비어 있지 않다면 가장 작은 원소 또는 그 근처(아래 lowStarts 의 +0~+5, 또는
// 수 버전/부 버전을 아주 크게 한 값) 중 하나는 반드시 집합 안에 있다.
// 사전 공개 버전은 "= 4.0.0-beta1" 처럼 정확히 지목되어야만 들어가므로 적힌 그대로 후보에 넣는다.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/apparentlymart/go-versions/versions"
	"github.com/apparentlymart/go-versions/versions/constraints"
)

const big = 999999999

var mention = regexp.MustCompile(`(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?`)

func num(s string) uint64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return big
	}
	return n
}

func candidates(line string) []versions.Version {
	type triple struct{ a, b, c uint64 }
	lowStarts := []triple{}
	for major := uint64(1); major <= 7; major++ {
		lowStarts = append(lowStarts, triple{major, 0, 0})
	}
	var out []versions.Version
	for _, m := range mention.FindAllStringSubmatch(line, -1) {
		z := triple{num(m[1]), num(m[2]), num(m[3])}
		lowStarts = append(lowStarts, z, triple{z.a, z.b, z.c + 1})
		if m[4] != "" {
			out = append(out, versions.Version{Major: z.a, Minor: z.b, Patch: z.c, Prerelease: versions.VersionExtra(m[4])})
		}
	}
	for _, l := range lowStarts {
		for d := uint64(0); d <= 5; d++ {
			out = append(out, versions.Version{Major: l.a, Minor: l.b, Patch: l.c + d})
		}
		out = append(out,
			versions.Version{Major: l.a, Minor: l.b, Patch: big},
			versions.Version{Major: l.a, Minor: l.b + 1, Patch: 0},
			versions.Version{Major: l.a, Minor: big, Patch: big})
	}
	return out
}

func main() {
	majorsOut := map[string]interface{}{}
	membersOut := map[string]interface{}{}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") { // 설명 줄
			continue
		}
		if parts := strings.SplitN(line, " @@ ", 2); len(parts) == 2 {
			spec, err := constraints.ParseRubyStyleMulti(parts[0])
			v, verr := versions.ParseVersion(parts[1])
			if err != nil || verr != nil {
				membersOut[line] = "error"
				continue
			}
			membersOut[line] = versions.MeetingConstraints(spec).Has(v)
			continue
		}
		spec, err := constraints.ParseRubyStyleMulti(line)
		if err != nil {
			majorsOut[line] = "error"
			continue
		}
		set := versions.MeetingConstraints(spec)
		seen := map[uint64]bool{}
		majors := []uint64{}
		for _, v := range candidates(line) {
			if v.Major >= 1 && v.Major <= 7 && set.Has(v) && !seen[v.Major] {
				seen[v.Major] = true
			}
		}
		for m := uint64(1); m <= 7; m++ {
			if seen[m] {
				majors = append(majors, m)
			}
		}
		majorsOut[line] = majors
	}
	b, _ := json.MarshalIndent(map[string]interface{}{"majors": majorsOut, "members": membersOut}, "", " ")
	fmt.Println(string(b))
}
