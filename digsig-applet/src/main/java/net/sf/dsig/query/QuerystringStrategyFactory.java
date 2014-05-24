package net.sf.dsig.query;

import net.sf.dsig.Strategy;
import net.sf.dsig.StrategyFactory;

public class QuerystringStrategyFactory implements StrategyFactory {

    @Override
    public String getName() {
        return "querystring";
    }

    @Override
    public Strategy getStrategy() {
        return new QuerystringStrategy();
    }

}
