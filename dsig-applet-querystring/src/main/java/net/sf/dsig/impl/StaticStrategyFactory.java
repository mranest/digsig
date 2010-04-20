/*
 * Copyright 2007-2010 Anestis Georgiadis
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

package net.sf.dsig.impl;

import net.sf.dsig.Environment;
import net.sf.dsig.Strategy;
import net.sf.dsig.StrategyFactory;

public class StaticStrategyFactory implements StrategyFactory {

	private static final StaticStrategyFactory SINGLETON = new StaticStrategyFactory();
	
	public static StaticStrategyFactory getSingleton() {
		return SINGLETON;
	}
	
	protected StaticStrategyFactory() { }
	
	@Override
	public String getName() {
		return "querystring";
	}

	@Override
	public Strategy getStrategy() {
		QuerystringStrategy s = new QuerystringStrategy();
		Environment.getSingleton().init(s);
		return s;
	}

}