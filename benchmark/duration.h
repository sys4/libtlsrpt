/*
    Copyright (C) 2024 sys4 AG
    Author Boris Lohner bl@sys4.de

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this program.
    If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DURATION_H
#define DURATION_H

#include <iostream>
#include <iomanip>
#include <time.h>
#include <unistd.h>
#include <algorithm>


using namespace std;

double duration(const struct timespec* ts_beg, const struct timespec* ts_fin) {
  const long nanos=1000000000;
  time_t deltas=ts_fin->tv_sec-ts_beg->tv_sec;
  long deltan=ts_fin->tv_nsec-ts_beg->tv_nsec;
  if(deltan<0) {
    deltan+=nanos;
    deltas-=1;
  }
  return deltas+(1.0*deltan)/nanos;
}


// C++ stuff

bool operator <(const struct timespec& ts_a, const struct timespec& ts_b) {
  if(ts_a.tv_sec<ts_b.tv_sec) return true;
  else if(ts_a.tv_sec==ts_b.tv_sec && ts_a.tv_nsec<ts_b.tv_nsec) return true;
  return false;
}

ostream& operator <<(ostream& o, const struct timespec& ts_a) {
  return o<<ts_a.tv_sec<<"_"<<setw(9)<<ts_a.tv_nsec;
}

// Rates


class Rate {
public:
  static const clockid_t clk=CLOCK_MONOTONIC;
  struct timespec ts_start;
  struct timespec ts_end;
  long count;

  Rate() : count(0) {}

  Rate(const struct timespec& start, const struct timespec& end, long n) : ts_start(start), ts_end(end), count(n) {}

  void start() {
    clock_gettime(clk,&ts_start);
  }

  void stop() {
    clock_gettime(clk,&ts_end);
  }

  void add(long n=1) {
    count+=n;
  }

  double duration() const {
    return ::duration(&ts_start, &ts_end);
  }

  double rate() const {
    return count/duration();
  }
};


Rate operator + (const Rate& a, const Rate& b) {
  return Rate(min(a.ts_start,b.ts_start), max(a.ts_end,b.ts_end), a.count+b.count);
}

ostream& operator <<(ostream& o, const Rate& r) {
  return o<<r.rate()<<" ("<<r.count<<" in "<<r.duration()<<" from "<<r.ts_start<<" till "<<r.ts_end<<")";
}

#endif // DURATION_H
