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

package net.sf.dsig;

import net.sf.dsig.impl.StaticStrategyFactory;

/**
 * <p>This factory interface creates {@link Strategy} objects.
 * 
 * <p>The concrete implementation is always bound to the
 * {@link StaticStrategyFactory} class.
 */
public interface StrategyFactory {

	String getName();
	
	Strategy getStrategy();
	
}
