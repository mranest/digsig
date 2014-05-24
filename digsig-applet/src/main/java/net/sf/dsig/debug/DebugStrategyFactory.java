package net.sf.dsig.debug;

import net.sf.dsig.Strategy;
import net.sf.dsig.StrategyFactory;

public class DebugStrategyFactory implements StrategyFactory {

    @Override
    public String getName() {
        return "debug";
    }

    @Override
    public Strategy getStrategy() {
        return new DebugStrategy();
    }

}
