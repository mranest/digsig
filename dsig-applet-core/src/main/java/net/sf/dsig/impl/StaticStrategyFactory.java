/*
 * Copyright 2007-2009 Anestis Georgiadis
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

import net.sf.dsig.Strategy;
import net.sf.dsig.StrategyFactory;

/**
 * <p>This singleton class is used to provide the {@link StrategyFactory} object
 * which is driving the digital signature process.
 * 
 * <p>The implementation of the core project is used to provide debugging
 * information only. Real implementations are found in each strategy project, e.g.
 * dsig-applet-xmldsig.
 */
public class StaticStrategyFactory implements StrategyFactory {

	private static final StaticStrategyFactory SINGLETON = 
		new StaticStrategyFactory();
	
	private StaticStrategyFactory() { }
	
	public static StaticStrategyFactory getSingleton() {
		return SINGLETON;
	}
	
	/**
	 * @see net.sf.dsig.StrategyFactory#getName()
	 */
	@Override
	public String getName() {
		return "debug";
	}
	
	/**
	 * @see net.sf.dsig.StrategyFactory#getStrategy()
	 */
	@Override
	public Strategy getStrategy() {
		return new DebugStrategy();
	}
	
}
