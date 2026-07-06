#!/usr/bin/env bash
# 性能开销基准测试：对每个场景，分别在「未加载工具(基线)」与「加载工具」两态下
# 跑等量固定负载，测量：
#   - 工具自身 CPU 占用%        -> 对应评分"CPU 开销"
#   - 工具峰值常驻内存 RSS       -> 对应评分"内存开销"
#   - 负载完成耗时增幅(slowdown%) -> 对应评分"时延/吞吐影响"
#
# 用法： bash scripts/benchmark.sh [scenario|all] [输出文件]
#   scenario ∈ cpu|io|mem|lock|syscall|all（默认 all）
set -uo pipefail

SC="${1:-all}"
OUT="${2:-}"
BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/ebpf-rca"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STRESS_NG="${STRESS_NG:-$ROOT/../.build_deps/bin/stress-ng}"
CLK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

[ -x "$BIN" ] || { echo "未找到二进制 $BIN，请先 make build" >&2; exit 1; }
if [ ! -x "$STRESS_NG" ] && command -v stress-ng >/dev/null 2>&1; then
	STRESS_NG="$(command -v stress-ng)"
fi

# 各场景的固定工作量负载（固定 ops/数据量，保证两态可比）
workload_cmd() {
	case "$1" in
	cpu)     echo "\"$STRESS_NG\" --cpu $(nproc) --cpu-method matrixprod --cpu-ops 8000" ;;
	lock)    echo "\"$STRESS_NG\" --mutex 8 --mutex-ops 300000" ;;
	mem)     echo "\"$STRESS_NG\" --vm 4 --vm-bytes 75% --vm-ops 3000" ;;
	io)      echo "fio --name=bench --filename=./fio-bench.img --size=1G --rw=randrw --rwmixread=70 --bs=4k --iodepth=64 --numjobs=4 --group_reporting" ;;
	syscall) echo "dd if=/dev/zero of=/dev/null bs=1 count=30000000" ;;
	esac
}

# 计时执行一条命令，打印墙钟秒数
time_cmd() {
	local s e
	s=$(date +%s.%N)
	eval "$1" >/dev/null 2>&1 || true
	e=$(date +%s.%N)
	awk "BEGIN{print $e-$s}"
}

bench_one() {
	local sc="$1" cmd base withv tpid tstart tend st rest u s hwm cpu slow rss
	cmd="$(workload_cmd "$sc")"
	[ -n "$cmd" ] || { echo "跳过未知场景 $sc" >&2; return; }
	echo "[bench] $sc：测基线..." >&2
	base=$(time_cmd "$cmd")

	echo "[bench] $sc：加载工具后再测..." >&2
	sudo "$BIN" --scenario "$sc" --duration 3600s >/dev/null 2>&1 &
	sleep 1.5
	tpid=$(pgrep -n -x ebpf-rca || true)
	tstart=$(date +%s.%N)
	withv=$(time_cmd "$cmd")
	tend=$(date +%s.%N)

	cpu=0; rss=0
	if [ -n "$tpid" ] && [ -r "/proc/$tpid/stat" ]; then
		st=$(cat "/proc/$tpid/stat")
		rest="${st##*) }"          # 跳过 comm，剩余首字段为 state(field3)
		u=$(echo "$rest" | awk '{print $12}')  # utime = field14
		s=$(echo "$rest" | awk '{print $13}')  # stime = field15
		hwm=$(awk '/VmHWM/{print $2}' "/proc/$tpid/status" 2>/dev/null || echo 0)
		cpu=$(awk "BEGIN{el=$tend-$tstart; if(el<=0)el=1; print (($u+$s)/$CLK)/el*100}")
		rss=$(awk "BEGIN{print ${hwm:-0}/1024}")
	fi
	[ -n "$tpid" ] && sudo kill "$tpid" 2>/dev/null || true
	[ "$sc" = "io" ] && rm -f ./fio-bench.img

	slow=$(awk "BEGIN{if($base<=0)print 0; else print ($withv-$base)/$base*100}")
	printf "| %-7s | %8.2f | %8.2f | %10.2f | %7.2f | %9.1f |\n" \
		"$sc" "$base" "$withv" "$slow" "$cpu" "$rss"
}

scenarios=()
if [ "$SC" = "all" ]; then scenarios=(cpu io mem lock syscall); else scenarios=("$SC"); fi

{
	echo "# ebpf-rca 性能开销基准 ($(date '+%Y-%m-%d %H:%M'))"
	echo
	echo "| 场景 | 基线(s) | 加载后(s) | 负载变慢% | 工具CPU% | 工具RSS(MB) |"
	echo "|------|---------|-----------|-----------|----------|-------------|"
	for sc in "${scenarios[@]}"; do bench_one "$sc"; done
	echo
	echo "> 负载变慢% = (加载后耗时-基线耗时)/基线 ×100，越小越好；工具CPU%/RSS 为 ebpf-rca 自身开销。"
} | { [ -n "$OUT" ] && tee "$OUT" || cat; }
